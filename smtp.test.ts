// Port of Go's net/smtp smtp_test.go (Go 1.26.4) to the node:test runner.
// Run with: node --test   (Node.js >= 24 strips the TypeScript types natively)
//
// The three real-TLS integration tests (TestNewClientWithTLS, TestTLSClient,
// TestTLSConnState) are ported faithfully against an in-process TLS server using
// the same embedded localhost cert/key as the Go suite.

import * as net from "node:net";
import * as tls from "node:tls";
import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";

import {
  Client,
  Conn,
  InMemoryConn,
  SocketConn,
  ServerInfo,
  PlainAuth,
  CRAMMD5Auth,
  Dial,
  NewClient,
  SendMail,
  testHooks,
} from "./smtp.ts";
import type { Auth, TLSConfig } from "./smtp.ts";

// crlf mirrors strings.Join(strings.Split(s, "\n"), "\r\n").
function crlf(s: string): string {
  return s.split("\n").join("\r\n");
}

function bytes(s: string): Buffer {
  return Buffer.from(s, "latin1");
}

// newFakeClient builds a Client over an in-memory connection (Go's faker +
// `&Client{Text: textproto.NewConn(fake), localName: "localhost"}`).
function newFakeClient(serverText: string): { c: Client; conn: InMemoryConn } {
  const conn = new InMemoryConn(serverText);
  const c = new Client(new Conn(conn));
  c.localName = "localhost";
  return { c, conn };
}

// -----------------------------------------------------------------------------
// TestAuth
// -----------------------------------------------------------------------------

test("TestAuth", () => {
  const authTests = [
    {
      auth: PlainAuth("", "user", "pass", "testserver"),
      challenges: [] as string[],
      name: "PLAIN",
      responses: ["\x00user\x00pass"],
    },
    {
      auth: PlainAuth("foo", "bar", "baz", "testserver"),
      challenges: [] as string[],
      name: "PLAIN",
      responses: ["foo\x00bar\x00baz"],
    },
    {
      auth: CRAMMD5Auth("user", "pass"),
      challenges: ["<123456.1322876914@testserver>"],
      name: "CRAM-MD5",
      responses: ["", "user 287eb355114cf5c471c26a875f1ca4ae"],
    },
  ];

  authTests.forEach((t, i) => {
    const [name, resp] = t.auth.Start(new ServerInfo("testserver", true, null));
    assert.strictEqual(name, t.name, `#${i} name`);
    assert.deepStrictEqual(
      Buffer.from(resp ?? new Uint8Array()),
      bytes(t.responses[0]),
      `#${i} response`,
    );
    for (let j = 0; j < t.challenges.length; j++) {
      const challenge = bytes(t.challenges[j]);
      const expected = bytes(t.responses[j + 1]);
      const r = t.auth.Next(challenge, true);
      assert.deepStrictEqual(
        Buffer.from(r ?? new Uint8Array()),
        expected,
        `#${i} challenge ${j}`,
      );
    }
  });
});

// -----------------------------------------------------------------------------
// TestAuthPlain
// -----------------------------------------------------------------------------

test("TestAuthPlain", () => {
  const tests = [
    { authName: "servername", server: new ServerInfo("servername", true, null), err: "" },
    // OK to use PlainAuth on localhost without TLS.
    { authName: "localhost", server: new ServerInfo("localhost", false, null), err: "" },
    // NOT OK on non-localhost, even if server says PLAIN is OK.
    {
      authName: "servername",
      server: new ServerInfo("servername", false, ["PLAIN"]),
      err: "unencrypted connection",
    },
    {
      authName: "servername",
      server: new ServerInfo("servername", false, ["CRAM-MD5"]),
      err: "unencrypted connection",
    },
    {
      authName: "servername",
      server: new ServerInfo("attacker", true, null),
      err: "wrong host name",
    },
  ];

  tests.forEach((tt, i) => {
    const auth = PlainAuth("foo", "bar", "baz", tt.authName);
    let got = "";
    try {
      auth.Start(tt.server);
    } catch (e) {
      got = (e as Error).message;
    }
    assert.strictEqual(got, tt.err, `#${i}`);
  });
});

// -----------------------------------------------------------------------------
// TestClientAuthTrimSpace (Issue 17794)
// -----------------------------------------------------------------------------

// toServerEmptyAuth only implements Start, returning ["FOOAUTH", null].
const toServerEmptyAuth: Auth = {
  Start() {
    return ["FOOAUTH", null];
  },
  Next() {
    throw new Error("unexpected call");
  },
};

test("TestClientAuthTrimSpace", async () => {
  const server = "220 hello world\r\n" + "200 some more";
  const conn = new InMemoryConn(server);
  const c = await NewClient(conn, "fake.host");
  c.tls = true;
  c.didHello = true;
  await c.Auth(toServerEmptyAuth).catch(() => {});
  await c.Close();
  assert.strictEqual(conn.writtenString(), "AUTH FOOAUTH\r\n*\r\nQUIT\r\n");
});

// -----------------------------------------------------------------------------
// TestBasic
// -----------------------------------------------------------------------------

const basicServer = `250 mx.google.com at your service
502 Unrecognized command.
250-mx.google.com at your service
250-SIZE 35651584
250-AUTH LOGIN PLAIN
250 8BITMIME
530 Authentication required
252 Send some mail, I'll try my best
250 User is valid
235 Accepted
250 Sender OK
250 Receiver OK
354 Go ahead
250 Data OK
221 OK
`;

const basicClient = `HELO localhost
EHLO localhost
EHLO localhost
MAIL FROM:<user@gmail.com> BODY=8BITMIME
VRFY user1@gmail.com
VRFY user2@gmail.com
AUTH PLAIN AHVzZXIAcGFzcw==
MAIL FROM:<user@gmail.com> BODY=8BITMIME
RCPT TO:<golang-nuts@googlegroups.com>
DATA
From: user@gmail.com
To: golang-nuts@googlegroups.com
Subject: Hooray for Go

Line 1
..Leading dot line .
Goodbye.
.
QUIT
`;

test("TestBasic", async () => {
  const { c, conn } = newFakeClient(crlf(basicServer));

  await c.helo();
  await assert.rejects(c.ehlo(), "Expected first EHLO to fail");
  await c.ehlo();

  c.didHello = true;
  {
    const [ok, args] = await c.Extension("aUtH");
    assert.ok(ok && args === "LOGIN PLAIN", "Expected AUTH supported");
  }
  {
    const [ok] = await c.Extension("DSN");
    assert.ok(!ok, "Shouldn't support DSN");
  }

  await assert.rejects(c.Mail("user@gmail.com"), "MAIL should require authentication");

  await assert.rejects(c.Verify("user1@gmail.com"), "First VRFY: expected no verification");
  await assert.rejects(
    c.Verify("user2@gmail.com>\r\nDATA\r\nAnother injected message body\r\n.\r\nQUIT\r\n"),
    "VRFY should have failed due to a message injection attempt",
  );
  await c.Verify("user2@gmail.com");

  // fake TLS so authentication won't complain
  c.tls = true;
  c.serverName = "smtp.google.com";
  await c.Auth(PlainAuth("", "user", "pass", "smtp.google.com"));

  await assert.rejects(
    c.Rcpt("golang-nuts@googlegroups.com>\r\nDATA\r\nInjected message body\r\n.\r\nQUIT\r\n"),
    "RCPT should have failed due to a message injection attempt",
  );
  await assert.rejects(
    c.Mail("user@gmail.com>\r\nDATA\r\nAnother injected message body\r\n.\r\nQUIT\r\n"),
    "MAIL should have failed due to a message injection attempt",
  );
  await c.Mail("user@gmail.com");
  await c.Rcpt("golang-nuts@googlegroups.com");

  const msg = `From: user@gmail.com
To: golang-nuts@googlegroups.com
Subject: Hooray for Go

Line 1
.Leading dot line .
Goodbye.`;
  const w = await c.Data();
  w.write(Buffer.from(msg, "utf8"));
  await w.close();

  await c.Quit();

  assert.strictEqual(conn.writtenString(), crlf(basicClient));
});

// -----------------------------------------------------------------------------
// TestHELOFailed
// -----------------------------------------------------------------------------

test("TestHELOFailed", async () => {
  const serverLines = `502 EH?
502 EH?
221 OK
`;
  const clientLines = `EHLO localhost
HELO localhost
QUIT
`;
  const { c, conn } = newFakeClient(crlf(serverLines));

  await assert.rejects(c.Hello("localhost"), "expected EHLO to fail");
  await c.Quit();
  assert.strictEqual(conn.writtenString(), crlf(clientLines));
});

// -----------------------------------------------------------------------------
// TestExtensions
// -----------------------------------------------------------------------------

test("TestExtensions/helo", async () => {
  const basicServerS = `250 mx.google.com at your service
250 Sender OK
221 Goodbye
`;
  const basicClientS = `HELO localhost
MAIL FROM:<user@gmail.com>
QUIT
`;
  const { c, conn } = newFakeClient(crlf(basicServerS));
  await c.helo();
  c.didHello = true;
  await c.Mail("user@gmail.com");
  await c.Quit();
  assert.strictEqual(conn.writtenString(), crlf(basicClientS));
});

test("TestExtensions/ehlo", async () => {
  const basicServerS = `250-mx.google.com at your service
250 SIZE 35651584
250 Sender OK
221 Goodbye
`;
  const basicClientS = `EHLO localhost
MAIL FROM:<user@gmail.com>
QUIT
`;
  const { c, conn } = newFakeClient(crlf(basicServerS));
  await c.Hello("localhost");
  assert.ok(!(await c.Extension("8BITMIME"))[0], "Shouldn't support 8BITMIME");
  assert.ok(!(await c.Extension("SMTPUTF8"))[0], "Shouldn't support SMTPUTF8");
  await c.Mail("user@gmail.com");
  await c.Quit();
  assert.strictEqual(conn.writtenString(), crlf(basicClientS));
});

test("TestExtensions/ehlo 8bitmime", async () => {
  const basicServerS = `250-mx.google.com at your service
250-SIZE 35651584
250 8BITMIME
250 Sender OK
221 Goodbye
`;
  const basicClientS = `EHLO localhost
MAIL FROM:<user@gmail.com> BODY=8BITMIME
QUIT
`;
  const { c, conn } = newFakeClient(crlf(basicServerS));
  await c.Hello("localhost");
  assert.ok((await c.Extension("8BITMIME"))[0], "Should support 8BITMIME");
  assert.ok(!(await c.Extension("SMTPUTF8"))[0], "Shouldn't support SMTPUTF8");
  await c.Mail("user@gmail.com");
  await c.Quit();
  assert.strictEqual(conn.writtenString(), crlf(basicClientS));
});

test("TestExtensions/ehlo smtputf8", async () => {
  const basicServerS = `250-mx.google.com at your service
250-SIZE 35651584
250 SMTPUTF8
250 Sender OK
221 Goodbye
`;
  const basicClientS = `EHLO localhost
MAIL FROM:<user+📧@gmail.com> SMTPUTF8
QUIT
`;
  const { c, conn } = newFakeClient(crlf(basicServerS));
  await c.Hello("localhost");
  assert.ok(!(await c.Extension("8BITMIME"))[0], "Shouldn't support 8BITMIME");
  assert.ok((await c.Extension("SMTPUTF8"))[0], "Should support SMTPUTF8");
  await c.Mail("user+📧@gmail.com");
  await c.Quit();
  assert.strictEqual(conn.writtenString(), crlf(basicClientS));
});

test("TestExtensions/ehlo 8bitmime smtputf8", async () => {
  const basicServerS = `250-mx.google.com at your service
250-SIZE 35651584
250-8BITMIME
250 SMTPUTF8
250 Sender OK
221 Goodbye
	`;
  const basicClientS = `EHLO localhost
MAIL FROM:<user+📧@gmail.com> BODY=8BITMIME SMTPUTF8
QUIT
`;
  const { c, conn } = newFakeClient(crlf(basicServerS));
  await c.Hello("localhost");
  c.didHello = true;
  assert.ok((await c.Extension("8BITMIME"))[0], "Should support 8BITMIME");
  assert.ok((await c.Extension("SMTPUTF8"))[0], "Should support SMTPUTF8");
  await c.Mail("user+📧@gmail.com");
  await c.Quit();
  assert.strictEqual(conn.writtenString(), crlf(basicClientS));
});

// -----------------------------------------------------------------------------
// TestNewClient / TestNewClient2
// -----------------------------------------------------------------------------

const newClientServer = `220 hello world
250-mx.google.com at your service
250-SIZE 35651584
250-AUTH LOGIN PLAIN
250 8BITMIME
221 OK
`;
const newClientClient = `EHLO localhost
QUIT
`;

test("TestNewClient", async () => {
  const conn = new InMemoryConn(crlf(newClientServer));
  const c = await NewClient(conn, "fake.host");
  {
    const [ok, args] = await c.Extension("aUtH");
    assert.ok(ok && args === "LOGIN PLAIN", "Expected AUTH supported");
  }
  {
    const [ok] = await c.Extension("DSN");
    assert.ok(!ok, "Shouldn't support DSN");
  }
  await c.Quit();
  assert.strictEqual(conn.writtenString(), crlf(newClientClient));
});

const newClient2Server = `220 hello world
502 EH?
250-mx.google.com at your service
250-SIZE 35651584
250-AUTH LOGIN PLAIN
250 8BITMIME
221 OK
`;
const newClient2Client = `EHLO localhost
HELO localhost
QUIT
`;

test("TestNewClient2", async () => {
  const conn = new InMemoryConn(crlf(newClient2Server));
  const c = await NewClient(conn, "fake.host");
  {
    const [ok] = await c.Extension("DSN");
    assert.ok(!ok, "Shouldn't support DSN");
  }
  await c.Quit();
  assert.strictEqual(conn.writtenString(), crlf(newClient2Client));
});

// -----------------------------------------------------------------------------
// TestHello
// -----------------------------------------------------------------------------

const baseHelloServer = `220 hello world
502 EH?
250-mx.google.com at your service
250 FEATURE
`;

const helloServer = [
  "",
  "502 Not implemented\n",
  "250 User is valid\n",
  "235 Accepted\n",
  "250 Sender ok\n",
  "",
  "250 Reset ok\n",
  "221 Goodbye\n",
  "250 Sender ok\n",
  "250 ok\n",
];

const baseHelloClient = `EHLO customhost
HELO customhost
`;

const helloClient = [
  "",
  "STARTTLS\n",
  "VRFY test@example.com\n",
  "AUTH PLAIN AHVzZXIAcGFzcw==\n",
  "MAIL FROM:<test@example.com>\n",
  "",
  "RSET\n",
  "QUIT\n",
  "VRFY test@example.com\n",
  "NOOP\n",
];

test("TestHello", async () => {
  assert.strictEqual(helloServer.length, helloClient.length, "Hello server/client size mismatch");

  for (let i = 0; i < helloServer.length; i++) {
    const server = crlf(baseHelloServer + helloServer[i]);
    const client = crlf(baseHelloClient + helloClient[i]);
    const conn = new InMemoryConn(server);
    const c = await NewClient(conn, "fake.host");
    c.localName = "customhost";

    switch (i) {
      case 0:
        await assert.rejects(
          c.Hello("hostinjection>\n\rDATA\r\nInjected message body\r\n.\r\nQUIT\r\n"),
          `#${i}: expected Hello to be rejected due to a message injection attempt`,
        );
        await c.Hello("customhost");
        break;
      case 1: {
        // StartTLS is rejected by the server with 502 before any TLS upgrade.
        try {
          await c.StartTLS(null);
        } catch (e) {
          assert.strictEqual((e as Error).message, `502 "Not implemented"`, `#${i}`);
        }
        break;
      }
      case 2:
        await c.Verify("test@example.com");
        break;
      case 3:
        c.tls = true;
        c.serverName = "smtp.google.com";
        await c.Auth(PlainAuth("", "user", "pass", "smtp.google.com"));
        break;
      case 4:
        await c.Mail("test@example.com");
        break;
      case 5: {
        const [ok] = await c.Extension("feature");
        assert.ok(!ok, `#${i}: Expected FEATURE not to be supported`);
        break;
      }
      case 6:
        await c.Reset();
        break;
      case 7:
        await c.Quit();
        break;
      case 8: {
        let verifyErr = false;
        try {
          await c.Verify("test@example.com");
        } catch {
          verifyErr = true;
        }
        if (verifyErr) {
          await assert.rejects(c.Hello("customhost"), `#${i}: Want error, got none`);
        }
        break;
      }
      case 9:
        await c.Noop();
        break;
      default:
        assert.fail("Unhandled command");
    }

    assert.strictEqual(conn.writtenString(), client, `command ${i}`);
  }
});

// -----------------------------------------------------------------------------
// TestSendMail (real TCP, no TLS)
// -----------------------------------------------------------------------------

// handleCanned replays canned server responses and records the client commands,
// mirroring the goroutine server in Go's TestSendMail.
async function handleCanned(socket: net.Socket, data: string[], cmdParts: Buffer[]): Promise<void> {
  const tc = new Conn(new SocketConn(socket));
  for (let i = 0; i < data.length && data[i] !== ""; i++) {
    await tc.PrintfLine("%s", [data[i]]);
    while (data[i].length >= 4 && data[i][3] === "-") {
      i++;
      await tc.PrintfLine("%s", [data[i]]);
    }
    if (data[i] === "221 Goodbye") return;
    let read = false;
    while (!read || data[i] === "354 Go ahead") {
      let msg: string;
      try {
        msg = await tc.ReadLine();
      } catch {
        return;
      }
      cmdParts.push(Buffer.from(msg + "\r\n", "utf8"));
      read = true;
      if (data[i] === "354 Go ahead" && msg === ".") break;
    }
  }
}

function startCannedServer(serverText: string): Promise<{
  address: string;
  commands: Promise<string>;
  server: net.Server;
}> {
  const data = serverText.split("\r\n");
  const cmdParts: Buffer[] = [];
  let resolveCommands!: (s: string) => void;
  let rejectCommands!: (e: unknown) => void;
  const commands = new Promise<string>((res, rej) => {
    resolveCommands = res;
    rejectCommands = rej;
  });
  const server = net.createServer((socket) => {
    handleCanned(socket, data, cmdParts).then(
      () => resolveCommands(Buffer.concat(cmdParts).toString("utf8")),
      (e) => rejectCommands(e),
    );
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const a = server.address() as net.AddressInfo;
      resolve({ address: `127.0.0.1:${a.port}`, commands, server });
    });
  });
}

const sendMailServer = `220 hello world
502 EH?
250 mx.google.com at your service
250 Sender ok
250 Receiver ok
354 Go ahead
250 Data ok
221 Goodbye
`;

const sendMailClient = `EHLO localhost
HELO localhost
MAIL FROM:<test@example.com>
RCPT TO:<other@example.com>
DATA
From: test@example.com
To: other@example.com
Subject: SendMail test

SendMail is working for me.
.
QUIT
`;

test("TestSendMail", async () => {
  const { address, commands, server } = await startCannedServer(crlf(sendMailServer));
  const mailMsg = crlf(`From: test@example.com
To: other@example.com
Subject: SendMail test

SendMail is working for me.
`);

  await assert.rejects(
    SendMail(
      address,
      null,
      "test@example.com",
      ["other@example.com>\n\rDATA\r\nInjected message body\r\n.\r\nQUIT\r\n"],
      mailMsg,
    ),
    "Expected SendMail to be rejected due to a message injection attempt",
  );

  await SendMail(address, null, "test@example.com", ["other@example.com"], mailMsg);

  const got = await commands;
  assert.strictEqual(got, crlf(sendMailClient));
  server.close();
});

// -----------------------------------------------------------------------------
// TestSendMailWithAuth (real TCP, no TLS)
// -----------------------------------------------------------------------------

test("TestSendMailWithAuth", async () => {
  const serverErr: Promise<void> = new Promise((resolve, reject) => {
    const server = net.createServer(async (socket) => {
      const tc = new Conn(new SocketConn(socket));
      try {
        await tc.PrintfLine("220 hello world");
        const msg = await tc.ReadLine();
        if (msg !== "EHLO localhost") {
          reject(new Error(`unexpected response ${JSON.stringify(msg)}; want "EHLO localhost"`));
        } else {
          await tc.PrintfLine("250 mx.google.com at your service");
          resolve();
        }
      } catch (e) {
        reject(e);
      } finally {
        server.close();
        socket.end();
      }
    });
    server.listen(0, "127.0.0.1", async () => {
      const a = server.address() as net.AddressInfo;
      const address = `127.0.0.1:${a.port}`;
      await assert.rejects(
        SendMail(
          address,
          PlainAuth("", "user", "pass", "smtp.google.com"),
          "test@example.com",
          ["other@example.com"],
          crlf(`From: test@example.com
To: other@example.com
Subject: SendMail test

SendMail is working for me.
`),
        ),
        (e: Error) => e.message === "smtp: server doesn't support AUTH",
        "SendMail: expected error because server doesn't support AUTH",
      );
    });
  });

  await serverErr;
});

// -----------------------------------------------------------------------------
// TestAuthFailed
// -----------------------------------------------------------------------------

const authFailedServer = `220 hello world
250-mx.google.com at your service
250 AUTH LOGIN PLAIN
535-Invalid credentials
535 please see www.example.com
221 Goodbye
`;
const authFailedClient = `EHLO localhost
AUTH PLAIN AHVzZXIAcGFzcw==
*
QUIT
`;

test("TestAuthFailed", async () => {
  const conn = new InMemoryConn(crlf(authFailedServer));
  const c = await NewClient(conn, "fake.host");
  c.tls = true;
  c.serverName = "smtp.google.com";

  await assert.rejects(
    c.Auth(PlainAuth("", "user", "pass", "smtp.google.com")),
    (e: Error) =>
      e.message === String.raw`535 "Invalid credentials\nplease see www.example.com"`,
    "Auth: expected error",
  );

  assert.strictEqual(conn.writtenString(), crlf(authFailedClient));
});

// -----------------------------------------------------------------------------
// Real-TLS integration tests
// -----------------------------------------------------------------------------

// localhostCert is a PEM-encoded TLS cert generated from src/crypto/tls:
//
//	go run generate_cert.go --rsa-bits 2048 --host 127.0.0.1,::1,example.com \
//		--ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
//
// The cert is valid from 1970 until ~2084, so default time verification works.
const localhostCert = `-----BEGIN CERTIFICATE-----
MIIDOjCCAiKgAwIBAgIRAM1/4MS0P4BXstjv50eeEsswDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAN5KVxPqz+h6hHC3QBg7ZwCZUql4Mbz7LvrYg+1CCRJnbWdK2MTP
s0Hi3CKzAEE6H52rPO1kqdcIo2D1Pw2PC7/TB6w8ASLumJQaZfBlbaZesbBfrtIu
iEtSKs/Iwxp57mn9RbjUkQgu3nSzjrgbFPrktz6lJ4LfC6azN62klkCTfspCDTjU
Sk58dlygIweYkIiWHAh5f+KvKT1aeheNMkLEx1KZ+Vz+Y/oEnEKjRxBcnUIwzIrZ
/fXbvRq8Fa9nLuDO8F0JDcM1Zg9gzPvFmdFy8fifC3H/uflcLVJp4ImtEWEoVPvt
OQLAwkulknsXACBVsCu/JgDU7Yda6Lk2Qq0CAwEAAaOBiDCBhTAOBgNVHQ8BAf8E
BAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQU3YcFHBnqY6c03/Ydoy94fa59+F8wLgYDVR0RBCcwJYILZXhhbXBsZS5j
b22HBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZIhvcNAQELBQADggEBANI7
DKO8ub7SOwesjcnt4fCfHumink2ixo2nxW/DpnNWBaAhA529HCAa7BgAFzQi/ES1
ALEFEr0Phad4KA+9qrQXIJsMV/GTPPsTVuluU9Uhq6V2M8YelQuoMDbnjZDWcdZV
0arpMdVT8vU4eOE7XWlo83gA08+1mX4WbEI5XaHDeKE4ogifCGamroOTzJidfMg/
tz01iclVt7Fkri6PYcUS+8ySYrc2XH+h1P2xZCNP8VhAsrpnqQqGS85TTSUkOgZt
ITQpEVnLIDwZSX0zYrN5z8gChVhzzMR8XmsOpMUBJL5qcpWrqy/ZswmsMvjVXmeN
zQLoXduc3BgLtaXv7O0=
-----END CERTIFICATE-----`;

// localhostKey is the private key for localhostCert (Go's testingKey rewrites
// "TESTING KEY" to "PRIVATE KEY"; the substituted form is stored here).
const localhostKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDeSlcT6s/oeoRw
t0AYO2cAmVKpeDG8+y762IPtQgkSZ21nStjEz7NB4twiswBBOh+dqzztZKnXCKNg
9T8Njwu/0wesPAEi7piUGmXwZW2mXrGwX67SLohLUirPyMMaee5p/UW41JEILt50
s464GxT65Lc+pSeC3wumszetpJZAk37KQg041EpOfHZcoCMHmJCIlhwIeX/iryk9
WnoXjTJCxMdSmflc/mP6BJxCo0cQXJ1CMMyK2f31270avBWvZy7gzvBdCQ3DNWYP
YMz7xZnRcvH4nwtx/7n5XC1SaeCJrRFhKFT77TkCwMJLpZJ7FwAgVbArvyYA1O2H
Wui5NkKtAgMBAAECggEAG4ZS//lcYyoAikB2pEl+uJlDng5vAjqMF62FsHQz0V6T
Mm4XJ0+cn7TqkzVc+7apwYk5kx+a1DCSomfbtd8XklocIhyP+3ZV2EjohHrat/YT
xIYkjIwMfl8fQ/lVB0s/1UnyPy+7AatkCklNi8h2sZZuhkhG+zKJK8wXQd4WaMpf
lcIaDijMdu0UTxUO+rISbjVpfL6HswTDUan6LhhxSa9F3zesLqgClKZIqzR8HCtM
83QwK+kiW00D3pVZT4qHfFouoPrszP/qm/17wjxBmk83rKKsF2AnmipBaHR+MHou
tCarJV35//h6z6m0VnAdrYhREif34s8H0pYbKng8oQKBgQD2lCbQu7W/FDu+D4u2
F9wXdjZGplwUHaldfMUsMvawMSt86JYg9yVCHPFnWLhCBYT9Q1B1biqXu5YHwvyi
F/SCVDBaN1pLAkNF5i3McgA2Zw9TbFwinJFpZSa5hSdBiZgpaFZj0KhJqA2ayaSQ
wbTt1aN2oix1wdd9VU7cb5v6GQKBgQDmyJ5JUee6Vc6r/iucO4JkTijzwfPkSqOc
zC7YmcWAE8oTWZf5ozM4vtuUhAyrfiHBaT8uUbyb3+E6MqRrZJmaAPEk9ALOvmZC
vSZD5htzzUsLi7bR7e9PJjXoT+3V1EB3VyHnMv6LCbx/vSs/XI8VrahlDoJAW4rP
UgGE703HtQKBgQCeIaLG6CqFMQejOrsBe0m1biUep9+TMvaDstmMH97eXZojD9H/
sB+fx4n1GguIo5uHBB1cQdtk1XNA5QY5OZ2f2zfrE2Z/hiL4d8ZVP6LtQKiuemaX
98q1SZ5NCZyERiZkH7qPZqgWHIUlCD3Wa7OJdyHOmfBjUH3Ord/WNGlWOQKBgQCv
RLVRoa6HSRuIa6PbJybD3sgjN61uN3FCZ588SKxBtMXHJEfTAyqncet5Q0AMDeK8
7J1bJCBFkSWP+V39YY119Dkvg1GOifNHxDcHYf5/V+4iep0Bmd4hEjfmkq1hs6yx
9a5907CVD3Pk31m06SqRoC0/cmFhVyR4hyM4PjWn8QKBgFz97Xe4VlllQ4v1lY3g
1LXoF3oVBAcIiDOfnJuJKKUNJuQPfp7Z2/gisX/8RDPO+iBqKesUQxTKC2v6MOue
YMR7L8AAn1wBFU5dioARmfBcVWBOpMZIHzHUqsnTqGzuIPTfnaZWxz13PbBxEiGS
+NeMNAdZn3grwXTdcD3VBVHs
-----END RSA PRIVATE KEY-----`;

// Mirror Go's init(): testHookStartTLS injects the test root CA. Node verifies
// against `ca`; the cert's 1970-2084 validity makes the default time work, so
// (unlike Go) no config.Time override is needed.
testHooks.startTLS = (config: TLSConfig) => {
  config.ca = localhostCert;
};

// serverHandle is an SMTP server finely tailored to deal with our own client
// only (Go's serverHandle): it speaks plaintext, advertises STARTTLS, upgrades
// the raw socket to TLS, then defers to serverHandleTLS.
async function serverHandle(socket: net.Socket): Promise<void> {
  const sc = new SocketConn(socket);
  const tc = new Conn(sc);
  await tc.PrintfLine("%s", ["220 127.0.0.1 ESMTP service ready"]);
  for (;;) {
    let line: string;
    try {
      line = await tc.ReadLine();
    } catch {
      return; // EOF
    }
    switch (line) {
      case "EHLO localhost":
        await tc.PrintfLine("%s", ["250-127.0.0.1 ESMTP offers a warm hug of welcome"]);
        await tc.PrintfLine("%s", ["250-STARTTLS"]);
        await tc.PrintfLine("%s", ["250 Ok"]);
        break;
      case "STARTTLS": {
        await tc.PrintfLine("%s", ["220 Go ahead"]);
        sc.detach();
        const tlsSock = new tls.TLSSocket(socket, {
          isServer: true,
          key: localhostKey,
          cert: localhostCert,
        });
        await new Promise<void>((res, rej) => {
          tlsSock.once("secure", () => res());
          tlsSock.once("error", rej);
        });
        return serverHandleTLS(tlsSock);
      }
      default:
        throw new Error(`unrecognized command: ${JSON.stringify(line)}`);
    }
  }
}

async function serverHandleTLS(socket: tls.TLSSocket): Promise<void> {
  const tc = new Conn(new SocketConn(socket));
  for (;;) {
    let line: string;
    try {
      line = await tc.ReadLine();
    } catch {
      return; // EOF
    }
    switch (line) {
      case "EHLO localhost":
        await tc.PrintfLine("%s", ["250 Ok"]);
        break;
      case "MAIL FROM:<joe1@example.com>":
        await tc.PrintfLine("%s", ["250 Ok"]);
        break;
      case "RCPT TO:<joe2@example.com>":
        await tc.PrintfLine("%s", ["250 Ok"]);
        break;
      case "DATA":
        await tc.PrintfLine("%s", ["354 send the mail data, end with ."]);
        await tc.PrintfLine("%s", ["250 Ok"]);
        break;
      case "Subject: test":
      case "":
      case "howdy!":
      case ".":
        break;
      case "QUIT":
        await tc.PrintfLine("%s", ["221 127.0.0.1 Service closing transmission channel"]);
        return;
      default:
        throw new Error(`unrecognized command during TLS: ${JSON.stringify(line)}`);
    }
  }
}

function newLocalListener(): Promise<{ server: net.Server; address: string }> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const a = server.address() as net.AddressInfo;
      resolve({ server, address: `127.0.0.1:${a.port}` });
    });
  });
}

// sendMail mirrors Go's sendMail helper used by TestTLSClient.
function sendMail(hostPort: string): Promise<void> {
  return SendMail(
    hostPort,
    null,
    "joe1@example.com",
    ["joe2@example.com"],
    Buffer.from("Subject: test\n\nhowdy!"),
  );
}

test("TestNewClientWithTLS", async () => {
  const server = tls.createServer(
    { key: localhostKey, cert: localhostCert },
    (socket) => {
      socket.write("220 SIGNS\r\n");
    },
  );
  await new Promise<void>((res) => server.listen(0, "127.0.0.1", () => res()));
  const a = server.address() as net.AddressInfo;

  const tlsSock = await new Promise<tls.TLSSocket>((res, rej) => {
    // config.InsecureSkipVerify = true on the Go side.
    const s = tls.connect(
      { host: "127.0.0.1", port: a.port, rejectUnauthorized: false },
      () => res(s),
    );
    s.once("error", rej);
  });

  const client = await NewClient(new SocketConn(tlsSock), `127.0.0.1:${a.port}`);
  assert.strictEqual(client.tls, true, "client.tls should be true over a TLS conn");

  await client.Close();
  tlsSock.destroy();
  await new Promise<void>((res) => server.close(() => res()));
});

test("TestTLSClient", async () => {
  const { server, address } = await newLocalListener();

  const serverErr = new Promise<void>((resolve, reject) => {
    server.once("connection", (socket) => {
      serverHandle(socket).then(resolve, reject);
    });
  });

  await sendMail(address);
  await serverErr;

  await new Promise<void>((res) => server.close(() => res()));
});

test("TestTLSConnState", async () => {
  const { server, address } = await newLocalListener();

  const serverErr = new Promise<void>((resolve, reject) => {
    server.once("connection", (socket) => {
      serverHandle(socket).then(resolve, reject);
    });
  });

  const c = await Dial(address);
  const cfg: TLSConfig = { ServerName: "example.com" };
  testHooks.startTLS!(cfg); // set the RootCAs (Node: `ca`)
  await c.StartTLS(cfg);

  const [cs, ok] = c.TLSConnectionState();
  assert.strictEqual(ok, true, "TLSConnectionState returned ok == false; want true");
  assert.ok(
    cs !== null && cs.version !== 0 && cs.handshakeComplete,
    "expected non-zero Version and HandshakeComplete",
  );

  await c.Quit();
  await serverErr;
  await new Promise<void>((res) => server.close(() => res()));
});
