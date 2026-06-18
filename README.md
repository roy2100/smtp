# net/smtp for TypeScript

A faithful, **zero-dependency** TypeScript port of the Go standard library package
[`net/smtp`](https://pkg.go.dev/net/smtp) (pinned to Go 1.26.4). Everything lives in
a single file, `smtp.ts`, and runs directly on **Node.js >= 24**, which strips
TypeScript types natively — no build step, no transpiler, no runtime dependencies.

It implements the SMTP client from RFC 5321 plus the `8BITMIME`, `AUTH`, and
`STARTTLS` extensions, along with the small slice of `net/textproto` the client
relies on.

## Requirements

- Node.js >= 24 (uses native TypeScript type stripping)

## Install / vendor

This is meant to be vendored: copy `smtp.ts` into your project. It imports only Node
builtins (`node:net`, `node:tls`, `node:crypto`, `node:buffer`).

```ts
import { SendMail, PlainAuth, Dial, NewClient } from "./smtp.ts";
```

The `@types/node` and `typescript` entries in `package.json` are dev-only (for type
checking) and are never required at runtime.

## Usage

### One-shot: `SendMail`

Mirrors Go's `smtp.SendMail`. It dials in **plaintext** and upgrades via `STARTTLS`
if the server advertises it (i.e. port 25/587 style):

```ts
import { SendMail, PlainAuth } from "./smtp.ts";

const msg = [
  "To: alice@example.com",
  "Subject: Hello",
  "",
  "Hello from smtp.ts!",
].join("\r\n");

await SendMail(
  "smtp.example.com:587",
  PlainAuth("", "user@example.com", "password", "smtp.example.com"),
  "user@example.com",
  ["alice@example.com"],
  msg,
);
```

### Step by step: `Client`

```ts
import { Dial, PlainAuth } from "./smtp.ts";

const c = await Dial("smtp.example.com:587");
const [ok] = await c.Extension("STARTTLS");
if (ok) await c.StartTLS({ ServerName: "smtp.example.com" });

await c.Auth(PlainAuth("", "user@example.com", "password", "smtp.example.com"));
await c.Mail("user@example.com");
await c.Rcpt("alice@example.com");

const w = await c.Data();
w.write("Subject: Hi\r\n\r\nbody\r\n");
await w.close();

await c.Quit();
```

### Implicit TLS (port 465 / SMTPS)

Like Go's `net/smtp`, this package's `Dial`/`SendMail` start in plaintext and use
`STARTTLS`. For **implicit TLS** (the whole connection is TLS from the first byte,
typically port 465) open the TLS socket yourself and hand it to `NewClient`, which
detects the TLS socket and marks the connection secure:

```ts
import * as tls from "node:tls";
import { SocketConn, NewClient, PlainAuth } from "./smtp.ts";

const socket = tls.connect({ host: "smtp.example.com", port: 465, servername: "smtp.example.com" });
await new Promise((res, rej) => socket.once("secureConnect", res).once("error", rej));

const c = await NewClient(new SocketConn(socket), "smtp.example.com");
await c.Auth(PlainAuth("", "user@example.com", "password", "smtp.example.com"));
// ... Mail / Rcpt / Data / Quit
```

A complete, runnable version (reading host/port/auth from a `config.json`, handling
both implicit TLS and STARTTLS) is in [`examples/send-email.ts`](examples/send-email.ts):

```bash
node examples/send-email.ts [recipient] [path/to/config.json]
```

## How it differs from Go

The API mirrors Go's, with these adaptations:

- **Async, throws instead of returning errors.** Methods return `Promise`s and throw
  on failure (`TextprotoError`, `ProtocolError`, or the `EOF` sentinel). `Auth` /
  `PlainAuth` / `CRAMMD5Auth` throw rather than returning an `error`.
- **`StartTLS` config** takes `{ ServerName, ... }` — a subset of Go's `tls.Config`
  passed through to Node's `tls.connect` (`ServerName` maps to `servername`).
- Method and field names follow the Go originals (e.g. `Mail`, `Rcpt`, `Data`,
  `Extension`, `Quit`).

## Testing

The suite is a port of Go's `smtp_test.go` onto the builtin `node:test` runner.

```bash
npm install     # one-time, dev deps only
npm test        # node --test
npm run typecheck

# single test
node --test --test-name-pattern="TestAuthFailed"
```

The three real-TLS integration tests are intentionally present-but-skipped; see
[`docs/plan-smtp-migration.md`](docs/plan-smtp-migration.md) for the scope decision.

## License

The original `net/smtp` is BSD-licensed by The Go Authors; this is a derivative port.
