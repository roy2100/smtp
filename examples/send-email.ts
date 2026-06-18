// Example: send an email using the vendored smtp.ts and a config.json.
//
// Run (Node.js >= 24):
//   node examples/send-email.ts [recipient] [path/to/config.json]
//
// Defaults: recipient = config.email.to, config = ../config.json
//
// Note on TLS: a `secure: true` config on port 465 means *implicit* TLS (SMTPS) —
// the whole connection is TLS from the first byte. Go's net/smtp (and this port's
// SendMail) only speaks plaintext + STARTTLS, so here we open the TLS socket
// ourselves and hand it to NewClient, which detects the TLS socket and sets
// client.tls = true (so PlainAuth will send credentials).

import * as net from "node:net";
import * as tls from "node:tls";
import { readFileSync } from "node:fs";

import { SocketConn, NewClient, PlainAuth, type Client } from "../smtp.ts";

interface Config {
  smtp: {
    host: string;
    port: number;
    secure: boolean;
    auth: { user: string; pass: string };
  };
  email: { from: string; to: string };
}

// Connect with implicit TLS (port 465 style) and return a ready Client.
async function dialImplicitTLS(host: string, port: number): Promise<Client> {
  const socket = await new Promise<tls.TLSSocket>((resolve, reject) => {
    const s = tls.connect({ host, port, servername: host });
    s.once("secureConnect", () => resolve(s));
    s.once("error", reject);
  });
  const conn = new SocketConn(socket);
  // host is used as the server name when authenticating.
  return NewClient(conn, host);
}

// Connect with plaintext + STARTTLS (port 587 / secure:false style).
async function dialStartTLS(host: string, port: number): Promise<Client> {
  const socket = await new Promise<net.Socket>((resolve, reject) => {
    const s = net.connect(port, host);
    s.once("connect", () => resolve(s));
    s.once("error", reject);
  });
  const client = await NewClient(new SocketConn(socket), host);
  const [ok] = await client.Extension("STARTTLS");
  if (ok) await client.StartTLS({ ServerName: host });
  return client;
}

// Build a minimal RFC 822 message with CRLF line endings.
function buildMessage(opts: {
  from: string;
  to: string;
  subject: string;
  body: string;
}): string {
  const headers = [
    `From: ${opts.from}`,
    `To: ${opts.to}`,
    `Subject: ${opts.subject}`,
    `Date: ${new Date().toUTCString()}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
  ];
  return headers.join("\r\n") + "\r\n\r\n" + opts.body.replace(/\r?\n/g, "\r\n");
}

async function main(): Promise<void> {
  const configPath = process.argv[3] ?? new URL("../config.json", import.meta.url);
  const config: Config = JSON.parse(readFileSync(configPath, "utf8"));

  const { host, port, secure, auth } = config.smtp;
  const from = config.email.from;
  const to = process.argv[2] ?? config.email.to;

  const client = secure
    ? await dialImplicitTLS(host, port)
    : await dialStartTLS(host, port);

  try {
    await client.Auth(PlainAuth("", auth.user, auth.pass, host));

    await client.Mail(from);
    await client.Rcpt(to);

    const w = await client.Data();
    w.write(
      buildMessage({
        from,
        to,
        subject: "Test from smtp.ts",
        body: "Hello!\n\nThis email was sent by the vendored net/smtp TypeScript port.\n",
      }),
    );
    await w.close();

    await client.Quit();
    console.log(`Sent to ${to} via ${host}:${port}`);
  } catch (err) {
    await client.Close().catch(() => {});
    throw err;
  }
}

main().catch((err) => {
  console.error("send failed:", err);
  process.exitCode = 1;
});
