// Package smtp implements the Simple Mail Transfer Protocol as defined in RFC 5321.
// It also implements the following extensions:
//
//	8BITMIME  RFC 1652
//	AUTH      RFC 2554
//	STARTTLS  RFC 3207
//
// This is a TypeScript port of the Go standard library package `net/smtp`
// (Go 1.26.4). It is a single, self-contained file with no third-party
// dependencies (only Node.js builtins) so it can be vendored directly and run
// on Node.js >= 24, which strips TypeScript types natively.
//
// The Go package returns errors; this port is async and throws instead.
// Field and method names follow the Go originals (including unexported ones,
// which become public here) so the ported test suite mirrors smtp_test.go.

import * as net from "node:net";
import * as tls from "node:tls";
import { createHmac } from "node:crypto";
import { Buffer } from "node:buffer";

// =============================================================================
// net/textproto port (the subset net/smtp depends on)
// =============================================================================

// An Error represents a numeric error response from a server.
// Its message matches Go's fmt.Sprintf("%03d %q", code, msg).
export class TextprotoError extends Error {
  code: number;
  msg: string;
  constructor(code: number, msg: string) {
    super(`${pad3(code)} ${goQuote(msg)}`);
    this.name = "TextprotoError";
    this.code = code;
    this.msg = msg;
  }
}

// A ProtocolError describes a protocol violation such as an invalid response
// or a hung-up connection.
export class ProtocolError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "ProtocolError";
  }
}

// EOF is a sentinel thrown when the connection has no more data, mirroring
// Go's io.EOF.
export const EOF = new Error("EOF");

function pad3(n: number): string {
  return String(n).padStart(3, "0");
}

// goQuote mirrors Go's strconv.Quote / %q for the inputs this package produces
// (printable text plus the usual control escapes).
function goQuote(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    switch (ch) {
      case '"':
        out += '\\"';
        break;
      case "\\":
        out += "\\\\";
        break;
      case "\n":
        out += "\\n";
        break;
      case "\r":
        out += "\\r";
        break;
      case "\t":
        out += "\\t";
        break;
      default:
        if (c < 0x20 || c === 0x7f) {
          out += "\\x" + c.toString(16).padStart(2, "0");
        } else {
          out += ch;
        }
    }
  }
  return out + '"';
}

function toStr(v: unknown): string {
  if (v instanceof Uint8Array) return Buffer.from(v).toString("latin1");
  return String(v);
}

function toHex(v: unknown): string {
  if (v instanceof Uint8Array) return Buffer.from(v).toString("hex");
  return Buffer.from(String(v), "utf8").toString("hex");
}

// sprintf implements the minimal subset of fmt verbs this package uses:
// %s, %x, %d (with 0-width like %03d), %q, and %%.
function sprintf(format: string, args: unknown[]): string {
  let out = "";
  let ai = 0;
  for (let i = 0; i < format.length; i++) {
    const ch = format[i];
    if (ch !== "%") {
      out += ch;
      continue;
    }
    i++;
    let spec = "";
    while (i < format.length && format[i] >= "0" && format[i] <= "9") {
      spec += format[i];
      i++;
    }
    const verb = format[i];
    switch (verb) {
      case "%":
        out += "%";
        break;
      case "s":
        out += toStr(args[ai++]);
        break;
      case "x":
        out += toHex(args[ai++]);
        break;
      case "d": {
        let s = String(args[ai++]);
        if (spec.startsWith("0")) s = s.padStart(parseInt(spec, 10), "0");
        out += s;
        break;
      }
      case "q":
        out += goQuote(toStr(args[ai++]));
        break;
      default:
        out += "%" + spec + (verb ?? "");
        break;
    }
  }
  return out;
}

function trimRightCRLF(s: string): string {
  return s.replace(/[\r\n]+$/, "");
}

// ByteConn is the transport seam (Go's net.Conn / io.ReadWriteCloser).
export interface ByteConn {
  // read resolves with the next chunk of bytes, or null at EOF.
  read(): Promise<Buffer | null>;
  write(b: Buffer): Promise<void>;
  close(): Promise<void>;
}

// parseCodeLine mirrors textproto.parseCodeLine. It never throws; it returns
// a possible Error as the 4th tuple element.
function parseCodeLine(
  line: string,
  expectCode: number,
): [number, boolean, string, Error | null] {
  if (line.length < 4 || (line[3] !== " " && line[3] !== "-")) {
    return [0, false, "", new ProtocolError(`short response: ${goQuote(line)}`)];
  }
  const continued = line[3] === "-";
  const codeStr = line.slice(0, 3);
  const code = Number(codeStr);
  if (!/^[0-9]{3}$/.test(codeStr) || code < 100) {
    return [
      0,
      false,
      "",
      new ProtocolError(`invalid response code: ${goQuote(line)}`),
    ];
  }
  const message = line.slice(4);
  let err: Error | null = null;
  if (
    (1 <= expectCode && expectCode < 10 && Math.floor(code / 100) !== expectCode) ||
    (10 <= expectCode && expectCode < 100 && Math.floor(code / 10) !== expectCode) ||
    (100 <= expectCode && expectCode < 1000 && code !== expectCode)
  ) {
    err = new TextprotoError(code, message);
  }
  return [code, continued, message, err];
}

// Reader reads lines and numeric response codes from a ByteConn.
class Reader {
  private buf: Buffer = Buffer.alloc(0);
  private eof = false;
  private conn: ByteConn;

  constructor(conn: ByteConn) {
    this.conn = conn;
  }

  // ReadLine reads a single line, eliding the final \n or \r\n. Throws EOF when
  // there is nothing left to read.
  async ReadLine(): Promise<string> {
    for (;;) {
      const nl = this.buf.indexOf(0x0a);
      if (nl >= 0) {
        let end = nl;
        if (end > 0 && this.buf[end - 1] === 0x0d) end--;
        const line = this.buf.subarray(0, end).toString("utf8");
        this.buf = this.buf.subarray(nl + 1);
        return line;
      }
      if (this.eof) {
        if (this.buf.length === 0) throw EOF;
        // Final line with no trailing newline (matches bufio.ReadLine at EOF).
        const line = this.buf.toString("utf8");
        this.buf = Buffer.alloc(0);
        return line;
      }
      const chunk = await this.conn.read();
      if (chunk === null) {
        this.eof = true;
        continue;
      }
      this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    }
  }

  private async readCodeLine(
    expectCode: number,
  ): Promise<[number, boolean, string, Error | null]> {
    const line = await this.ReadLine();
    return parseCodeLine(line, expectCode);
  }

  // ReadResponse reads a (possibly multi-line) response. Returns [code, message]
  // and throws on protocol/IO errors or a status code that doesn't match
  // expectCode (expectCode <= 0 disables the check).
  async ReadResponse(expectCode: number): Promise<[number, string]> {
    const [code, continuedInit, first, err0] =
      await this.readCodeLine(expectCode);
    let continued = continuedInit;
    const multi = continued;
    let message = first;
    let err = err0;
    while (continued) {
      const line = await this.ReadLine();
      const [code2, cont2, moreMessage, err2] = parseCodeLine(line, 0);
      if (err2 !== null || code2 !== code) {
        message += "\n" + trimRightCRLF(line);
        continued = true;
        continue;
      }
      continued = cont2;
      message += "\n" + moreMessage;
    }
    if (err !== null && multi && message !== "") {
      // Replace the one-line error message with all lines (full message).
      err = new TextprotoError(code, message);
    }
    if (err !== null) throw err;
    return [code, message];
  }
}

// dot-encoding writer states (mirrors textproto writer.go).
const wstateBegin = 0;
const wstateBeginLine = 1;
const wstateCR = 2;
const wstateData = 3;

// DotWriter writes a dot-encoded block: it escapes leading dots, translates \n
// into \r\n, and appends the final .\r\n on Close. Writes are buffered and
// flushed on Close (the byte output is identical to Go's incremental writer).
class DotWriter {
  private state = wstateBegin;
  private out: number[] = [];
  private writer: Writer;
  private conn: ByteConn;

  constructor(writer: Writer, conn: ByteConn) {
    this.writer = writer;
    this.conn = conn;
  }

  Write(b: Uint8Array): void {
    for (let n = 0; n < b.length; n++) {
      const c = b[n];
      switch (this.state) {
        case wstateBegin:
        case wstateBeginLine:
          this.state = wstateData;
          if (c === 0x2e) this.out.push(0x2e); // escape leading dot
          // fallthrough into wstateData handling
          if (c === 0x0d) this.state = wstateCR;
          if (c === 0x0a) {
            this.out.push(0x0d);
            this.state = wstateBeginLine;
          }
          break;
        case wstateData:
          if (c === 0x0d) this.state = wstateCR;
          if (c === 0x0a) {
            this.out.push(0x0d);
            this.state = wstateBeginLine;
          }
          break;
        case wstateCR:
          this.state = wstateData;
          if (c === 0x0a) this.state = wstateBeginLine;
          break;
      }
      this.out.push(c);
    }
  }

  async Close(): Promise<void> {
    this.writer._clearDot(this);
    if (this.state === wstateBegin || this.state === wstateData) {
      this.out.push(0x0d, 0x0a, 0x2e, 0x0d, 0x0a);
    } else if (this.state === wstateCR) {
      this.out.push(0x0a, 0x2e, 0x0d, 0x0a);
    } else {
      // wstateBeginLine
      this.out.push(0x2e, 0x0d, 0x0a);
    }
    await this.conn.write(Buffer.from(this.out));
  }
}

// Writer writes requests/responses to a ByteConn.
class Writer {
  private dot: DotWriter | null = null;
  private conn: ByteConn;

  constructor(conn: ByteConn) {
    this.conn = conn;
  }

  async PrintfLine(format: string, args: unknown[] = []): Promise<void> {
    await this.closeDot();
    const line = sprintf(format, args) + "\r\n";
    await this.conn.write(Buffer.from(line, "utf8"));
  }

  DotWriter(): DotWriter {
    this.dot = new DotWriter(this, this.conn);
    return this.dot;
  }

  _clearDot(d: DotWriter): void {
    if (this.dot === d) this.dot = null;
  }

  private async closeDot(): Promise<void> {
    if (this.dot) {
      const d = this.dot;
      this.dot = null;
      await d.Close();
    }
  }
}

// Pipeline manages in-order request/response sequencing. In this single-threaded
// async port there is never concurrent pipelining, so the sequencer collapses to
// a simple id counter (behaviorally identical to textproto.Pipeline here).
class Pipeline {
  private idCounter = 0;
  Next(): number {
    return this.idCounter++;
  }
  StartRequest(_id: number): void {}
  EndRequest(_id: number): void {}
  StartResponse(_id: number): void {}
  EndResponse(_id: number): void {}
}

// Conn is a textual network protocol connection (textproto.Conn).
export class Conn {
  conn: ByteConn;
  private reader: Reader;
  private writer: Writer;
  private pipeline: Pipeline;

  constructor(conn: ByteConn) {
    this.conn = conn;
    this.reader = new Reader(conn);
    this.writer = new Writer(conn);
    this.pipeline = new Pipeline();
  }

  async Cmd(format: string, args: unknown[] = []): Promise<number> {
    const id = this.pipeline.Next();
    this.pipeline.StartRequest(id);
    await this.writer.PrintfLine(format, args);
    this.pipeline.EndRequest(id);
    return id;
  }

  StartResponse(id: number): void {
    this.pipeline.StartResponse(id);
  }

  EndResponse(id: number): void {
    this.pipeline.EndResponse(id);
  }

  ReadLine(): Promise<string> {
    return this.reader.ReadLine();
  }

  ReadResponse(expectCode: number): Promise<[number, string]> {
    return this.reader.ReadResponse(expectCode);
  }

  PrintfLine(format: string, args: unknown[] = []): Promise<void> {
    return this.writer.PrintfLine(format, args);
  }

  DotWriter(): DotWriter {
    return this.writer.DotWriter();
  }

  async Close(): Promise<void> {
    await this.conn.close();
  }
}

export function NewConn(conn: ByteConn): Conn {
  return new Conn(conn);
}

// =============================================================================
// Transports
// =============================================================================

// SocketConn adapts a Node socket (net or TLS) to ByteConn using a pull-based
// reader so STARTTLS can hand the underlying socket to tls.connect without
// over-consuming bytes.
export class SocketConn implements ByteConn {
  socket: net.Socket | tls.TLSSocket;
  private ended = false;
  private err: Error | null = null;
  private wake: (() => void) | null = null;

  constructor(socket: net.Socket | tls.TLSSocket) {
    this.socket = socket;
    socket.on("readable", () => this.signal());
    socket.on("end", () => {
      this.ended = true;
      this.signal();
    });
    socket.on("close", () => {
      this.ended = true;
      this.signal();
    });
    socket.on("error", (e: Error) => {
      this.err = e;
      this.signal();
    });
  }

  private signal(): void {
    if (this.wake) {
      const w = this.wake;
      this.wake = null;
      w();
    }
  }

  async read(): Promise<Buffer | null> {
    for (;;) {
      if (this.err) throw this.err;
      const chunk = this.socket.read() as Buffer | null;
      if (chunk !== null && chunk !== undefined) return chunk;
      if (this.ended) return null;
      await new Promise<void>((res) => {
        this.wake = res;
      });
    }
  }

  write(b: Buffer): Promise<void> {
    return new Promise((res, rej) => {
      this.socket.write(b, (e) => (e ? rej(e) : res()));
    });
  }

  close(): Promise<void> {
    return new Promise((res) => {
      this.socket.end(() => res());
    });
  }

  detach(): void {
    this.socket.removeAllListeners("readable");
    this.socket.removeAllListeners("end");
    this.socket.removeAllListeners("close");
    this.socket.removeAllListeners("error");
  }
}

// InMemoryConn is an in-memory ByteConn used by tests (Go's faker). It serves
// the preloaded server bytes and records everything written by the client.
export class InMemoryConn implements ByteConn {
  private pos = 0;
  private readBuf: Buffer;
  readonly written: Buffer[] = [];
  closed = false;

  constructor(serverData: string | Buffer = "") {
    this.readBuf = Buffer.isBuffer(serverData)
      ? serverData
      : Buffer.from(serverData, "utf8");
  }

  async read(): Promise<Buffer | null> {
    if (this.pos >= this.readBuf.length) return null;
    const chunk = this.readBuf.subarray(this.pos);
    this.pos = this.readBuf.length;
    return chunk;
  }

  async write(b: Buffer): Promise<void> {
    this.written.push(Buffer.from(b));
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  writtenString(): string {
    return Buffer.concat(this.written).toString("utf8");
  }
}

// =============================================================================
// auth.go port
// =============================================================================

// ServerInfo records information about an SMTP server.
export class ServerInfo {
  Name: string;
  TLS: boolean;
  Auth: string[] | null;
  constructor(name: string, tls: boolean, auth: string[] | null) {
    this.Name = name;
    this.TLS = tls;
    this.Auth = auth;
  }
}

// Auth is implemented by an SMTP authentication mechanism. Start/Next throw on
// error instead of returning one.
export interface Auth {
  // Start begins authentication, returning [proto, toServer].
  Start(server: ServerInfo): [string, Uint8Array | null];
  // Next continues authentication, returning toServer (or null).
  Next(fromServer: Uint8Array | null, more: boolean): Uint8Array | null;
}

function isLocalhost(name: string): boolean {
  return name === "localhost" || name === "127.0.0.1" || name === "::1";
}

class plainAuth implements Auth {
  private identity: string;
  private username: string;
  private password: string;
  private host: string;
  constructor(identity: string, username: string, password: string, host: string) {
    this.identity = identity;
    this.username = username;
    this.password = password;
    this.host = host;
  }

  Start(server: ServerInfo): [string, Uint8Array | null] {
    // Must have TLS, or else localhost server.
    if (!server.TLS && !isLocalhost(server.Name)) {
      throw new Error("unencrypted connection");
    }
    if (server.Name !== this.host) {
      throw new Error("wrong host name");
    }
    const resp = Buffer.from(
      this.identity + "\x00" + this.username + "\x00" + this.password,
      "utf8",
    );
    return ["PLAIN", resp];
  }

  Next(_fromServer: Uint8Array | null, more: boolean): Uint8Array | null {
    if (more) {
      // We've already sent everything.
      throw new Error("unexpected server challenge");
    }
    return null;
  }
}

// PlainAuth returns an Auth that implements the PLAIN authentication mechanism
// (RFC 4616). It only sends credentials over TLS or to localhost.
export function PlainAuth(
  identity: string,
  username: string,
  password: string,
  host: string,
): Auth {
  return new plainAuth(identity, username, password, host);
}

class cramMD5Auth implements Auth {
  private username: string;
  private secret: string;
  constructor(username: string, secret: string) {
    this.username = username;
    this.secret = secret;
  }

  Start(_server: ServerInfo): [string, Uint8Array | null] {
    return ["CRAM-MD5", null];
  }

  Next(fromServer: Uint8Array | null, more: boolean): Uint8Array | null {
    if (more) {
      const d = createHmac("md5", this.secret);
      d.update(Buffer.from(fromServer ?? new Uint8Array()));
      return Buffer.from(`${this.username} ${d.digest("hex")}`, "utf8");
    }
    return null;
  }
}

// CRAMMD5Auth returns an Auth implementing the CRAM-MD5 mechanism (RFC 2195).
export function CRAMMD5Auth(username: string, secret: string): Auth {
  return new cramMD5Auth(username, secret);
}

// =============================================================================
// smtp.go port
// =============================================================================

function b64encode(b: Uint8Array | null): string {
  return Buffer.from(b ?? new Uint8Array()).toString("base64");
}

function b64decode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

function validateLine(line: string): void {
  if (line.includes("\n") || line.includes("\r")) {
    throw new Error("smtp: A line must not contain CR or LF");
  }
}

// TLSConfig is a small subset of Go's tls.Config, passed through to
// tls.connect. ServerName maps to tls.connect's `servername`.
export interface TLSConfig {
  ServerName?: string;
  [key: string]: unknown;
}

// ConnectionState mirrors the bits of tls.ConnectionState this package reports.
export interface ConnectionState {
  version: number;
  handshakeComplete: boolean;
  protocol: string;
  cipher: tls.CipherNameAndProtocol | undefined;
}

// testHooks mirrors Go's testHookStartTLS; tests can set startTLS to mutate the
// TLS config (e.g. inject a root CA) just before SendMail upgrades.
export const testHooks: { startTLS: ((config: TLSConfig) => void) | null } = {
  startTLS: null,
};

// A Client represents a client connection to an SMTP server.
export class Client {
  // Text is the underlying textproto connection, exported for extensions.
  Text!: Conn;
  // keep a reference to the connection so it can be upgraded to TLS later.
  conn: ByteConn | null = null;
  // whether the Client is using TLS.
  tls = false;
  serverName = "";
  // map of supported extensions.
  ext: Map<string, string> | null = null;
  // supported auth mechanisms.
  auth: string[] = [];
  // the name to use in HELO/EHLO.
  localName = "localhost";
  // whether we've said HELO/EHLO.
  didHello = false;
  // the error from the hello.
  helloError: Error | null = null;

  constructor(text?: Conn, conn?: ByteConn) {
    if (text) this.Text = text;
    if (conn) this.conn = conn;
  }

  // Close closes the connection.
  async Close(): Promise<void> {
    await this.Text.Close();
  }

  // hello runs a hello exchange if needed.
  async hello(): Promise<void> {
    if (!this.didHello) {
      this.didHello = true;
      try {
        await this.ehlo();
      } catch {
        try {
          await this.helo();
          this.helloError = null;
        } catch (e) {
          this.helloError = e as Error;
        }
      }
    }
    if (this.helloError !== null) throw this.helloError;
  }

  // Hello sends a HELO or EHLO to the server as the given host name.
  async Hello(localName: string): Promise<void> {
    validateLine(localName);
    if (this.didHello) {
      throw new Error("smtp: Hello called after other methods");
    }
    this.localName = localName;
    await this.hello();
  }

  // cmd sends a command and returns [code, message], throwing on error.
  async cmd(
    expectCode: number,
    format: string,
    ...args: unknown[]
  ): Promise<[number, string]> {
    const id = await this.Text.Cmd(format, args);
    this.Text.StartResponse(id);
    try {
      return await this.Text.ReadResponse(expectCode);
    } finally {
      this.Text.EndResponse(id);
    }
  }

  // helo sends the HELO greeting (used only when the server doesn't support EHLO).
  async helo(): Promise<void> {
    this.ext = null;
    await this.cmd(250, "HELO %s", this.localName);
  }

  // ehlo sends the EHLO (extended hello) greeting.
  async ehlo(): Promise<void> {
    const [, msg] = await this.cmd(250, "EHLO %s", this.localName);
    const ext = new Map<string, string>();
    let extList = msg.split("\n");
    if (extList.length > 1) {
      extList = extList.slice(1);
      for (const line of extList) {
        const idx = line.indexOf(" ");
        if (idx >= 0) {
          ext.set(line.slice(0, idx), line.slice(idx + 1));
        } else {
          ext.set(line, "");
        }
      }
    }
    const mechs = ext.get("AUTH");
    if (mechs !== undefined) {
      this.auth = mechs.split(" ");
    }
    this.ext = ext;
  }

  // StartTLS sends STARTTLS and encrypts all further communication.
  async StartTLS(config: TLSConfig | null): Promise<void> {
    await this.hello();
    await this.cmd(220, "STARTTLS");
    if (!(this.conn instanceof SocketConn)) {
      throw new Error("smtp: StartTLS requires a socket connection");
    }
    const sc = this.conn;
    const rawSocket = sc.socket as net.Socket;
    sc.detach();
    const tlsSock = await upgradeToTLS(rawSocket, config ?? {});
    this.conn = new SocketConn(tlsSock);
    this.Text = new Conn(this.conn);
    this.tls = true;
    await this.ehlo();
  }

  // TLSConnectionState returns the client's TLS connection state.
  TLSConnectionState(): [ConnectionState | null, boolean] {
    if (
      this.conn instanceof SocketConn &&
      this.conn.socket instanceof tls.TLSSocket
    ) {
      const s = this.conn.socket;
      const proto = s.getProtocol() ?? "";
      return [
        {
          version: proto ? 1 : 0,
          handshakeComplete: true,
          protocol: proto,
          cipher: s.getCipher(),
        },
        true,
      ];
    }
    return [null, false];
  }

  // Verify checks the validity of an email address on the server.
  async Verify(addr: string): Promise<void> {
    validateLine(addr);
    await this.hello();
    await this.cmd(250, "VRFY %s", addr);
  }

  // Auth authenticates a client using the provided authentication mechanism.
  // A failed authentication closes the connection.
  async Auth(a: Auth): Promise<void> {
    await this.hello();
    let mech: string;
    let resp: Uint8Array | null;
    try {
      [mech, resp] = a.Start(new ServerInfo(this.serverName, this.tls, this.auth));
    } catch (err) {
      await this.Quit().catch(() => {});
      throw err;
    }
    let resp64 = b64encode(resp);
    let [code, msg64] = await this.cmd(
      0,
      "%s",
      `AUTH ${mech} ${resp64}`.trim(),
    );
    for (;;) {
      let msg: Uint8Array = new Uint8Array();
      let protoErr: Error | null = null;
      switch (code) {
        case 334:
          try {
            msg = b64decode(msg64);
          } catch (e) {
            protoErr = e as Error;
          }
          break;
        case 235:
          // the last message isn't base64 because it isn't a challenge.
          msg = Buffer.from(msg64, "utf8");
          break;
        default:
          protoErr = new TextprotoError(code, msg64);
      }
      if (protoErr === null) {
        try {
          resp = a.Next(msg, code === 334);
        } catch (e) {
          protoErr = e as Error;
        }
      }
      if (protoErr !== null) {
        // abort the AUTH
        await this.cmd(501, "*").catch(() => {});
        await this.Quit().catch(() => {});
        throw protoErr;
      }
      if (resp === null) break;
      resp64 = b64encode(resp);
      [code, msg64] = await this.cmd(0, "%s", resp64);
    }
  }

  // Mail issues a MAIL command to the server.
  async Mail(from: string): Promise<void> {
    validateLine(from);
    await this.hello();
    let cmdStr = "MAIL FROM:<%s>";
    if (this.ext !== null) {
      if (this.ext.has("8BITMIME")) cmdStr += " BODY=8BITMIME";
      if (this.ext.has("SMTPUTF8")) cmdStr += " SMTPUTF8";
    }
    await this.cmd(250, cmdStr, from);
  }

  // Rcpt issues a RCPT command to the server.
  async Rcpt(to: string): Promise<void> {
    validateLine(to);
    await this.cmd(25, "RCPT TO:<%s>", to);
  }

  // Data issues a DATA command and returns a writer for the mail headers and
  // body. Close the writer before calling any other method.
  async Data(): Promise<DataWriter> {
    await this.cmd(354, "DATA");
    return new DataWriter(this, this.Text.DotWriter());
  }

  // Extension reports whether an extension is supported by the server.
  async Extension(ext: string): Promise<[boolean, string]> {
    try {
      await this.hello();
    } catch {
      return [false, ""];
    }
    if (this.ext === null) return [false, ""];
    ext = ext.toUpperCase();
    const param = this.ext.get(ext);
    if (param === undefined) return [false, ""];
    return [true, param];
  }

  // Reset sends the RSET command, aborting the current mail transaction.
  async Reset(): Promise<void> {
    await this.hello();
    await this.cmd(250, "RSET");
  }

  // Noop sends the NOOP command.
  async Noop(): Promise<void> {
    await this.hello();
    await this.cmd(250, "NOOP");
  }

  // Quit sends the QUIT command and closes the connection.
  async Quit(): Promise<void> {
    try {
      await this.hello(); // ignore error; we're quitting anyhow
    } catch {
      // ignore
    }
    await this.cmd(221, "QUIT");
    await this.Text.Close();
  }
}

// DataWriter is the writer returned by Client.Data (Go's dataCloser).
export class DataWriter {
  private client: Client;
  private dot: DotWriter;
  constructor(client: Client, dot: DotWriter) {
    this.client = client;
    this.dot = dot;
  }

  write(data: Buffer | Uint8Array | string): void {
    const b = typeof data === "string" ? Buffer.from(data, "utf8") : data;
    this.dot.Write(b);
  }

  async close(): Promise<void> {
    await this.dot.Close();
    await this.client.Text.ReadResponse(250);
  }
}

function splitHostPort(addr: string): { host: string; port: number } {
  const i = addr.lastIndexOf(":");
  if (i < 0) return { host: addr, port: 0 };
  let host = addr.slice(0, i);
  const port = parseInt(addr.slice(i + 1), 10) || 0;
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  return { host, port };
}

function upgradeToTLS(
  socket: net.Socket,
  config: TLSConfig,
): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const { ServerName, ...rest } = config;
    const tlsSock = tls.connect({
      socket,
      servername: ServerName,
      ...(rest as tls.ConnectionOptions),
    });
    tlsSock.once("secureConnect", () => resolve(tlsSock));
    tlsSock.once("error", reject);
  });
}

// Dial returns a new Client connected to an SMTP server at addr.
// addr must include a port, as in "mail.example.com:smtp".
export async function Dial(addr: string): Promise<Client> {
  const { host, port } = splitHostPort(addr);
  const socket: net.Socket = await new Promise((resolve, reject) => {
    const s = net.connect(port, host);
    s.once("connect", () => resolve(s));
    s.once("error", reject);
  });
  const conn = new SocketConn(socket);
  return NewClient(conn, host);
}

// NewClient returns a new Client using an existing connection and host as a
// server name to be used when authenticating.
export async function NewClient(conn: ByteConn, host: string): Promise<Client> {
  const text = new Conn(conn);
  try {
    await text.ReadResponse(220);
  } catch (e) {
    await text.Close();
    throw e;
  }
  const c = new Client(text, conn);
  c.serverName = host;
  c.localName = "localhost";
  c.tls = conn instanceof SocketConn && conn.socket instanceof tls.TLSSocket;
  return c;
}

// SendMail connects to the server at addr, switches to TLS if possible,
// authenticates with the optional mechanism a if possible, and then sends an
// email from address from, to addresses to, with message msg.
export async function SendMail(
  addr: string,
  a: Auth | null,
  from: string,
  to: string[],
  msg: Buffer | Uint8Array | string,
): Promise<void> {
  validateLine(from);
  for (const recp of to) validateLine(recp);
  const c = await Dial(addr);
  try {
    await c.hello();
    const [ok] = await c.Extension("STARTTLS");
    if (ok) {
      const config: TLSConfig = { ServerName: c.serverName };
      if (testHooks.startTLS) testHooks.startTLS(config);
      await c.StartTLS(config);
    }
    if (a !== null && c.ext !== null) {
      if (!c.ext.has("AUTH")) {
        throw new Error("smtp: server doesn't support AUTH");
      }
      await c.Auth(a);
    }
    await c.Mail(from);
    for (const addr2 of to) await c.Rcpt(addr2);
    const w = await c.Data();
    w.write(typeof msg === "string" ? Buffer.from(msg, "utf8") : msg);
    await w.close();
    await c.Quit();
  } finally {
    await c.Close().catch(() => {});
  }
}
