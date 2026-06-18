# Plan: Migrate Go `net/smtp` to a single-file TypeScript module

## Goal
Port the Go standard library package `net/smtp` (Go 1.26.4 source, vendored under
`./go-go1.26.4`) to TypeScript so it can be used as a zero-dependency vendor module
that runs directly on Node.js >= 24 (which strips TypeScript types natively). The port
must reproduce the package's observable behavior, including the SMTP wire protocol and
the supporting `net/textproto` primitives the client relies on, and it must carry over
the test suite.

## Scope
Included:
- `smtp.ts` — single self-contained file, no third-party dependencies (Node builtins
  `node:net`, `node:tls`, `node:crypto` only). Contains:
  - The `net/textproto` subset the client needs: `Error`, `ProtocolError`, a buffered
    line `Reader`, a `Writer` with `PrintfLine` + dot-encoding `DotWriter`, the
    `Pipeline` sequencer, and the `Conn` wrapper.
  - The SMTP `Client` (`Dial`, `NewClient`, `Hello`, `StartTLS`, `Verify`, `Auth`,
    `Mail`, `Rcpt`, `Data`, `Extension`, `Reset`, `Noop`, `Quit`, `Close`,
    `TLSConnectionState`) and the package-level `SendMail`.
  - `Auth` interface plus `PlainAuth` / `CRAMMD5Auth` (auth.go).
  - A `ByteConn` transport abstraction with a real-socket implementation and an
    in-memory implementation for tests (mirrors Go's `net.Conn` / `faker`).
- `smtp.test.ts` — faithful port of `smtp_test.go` using the builtin `node:test`
  runner (`node --test`), including the embedded localhost TLS cert/key.

Out of scope:
- The frozen package's unused `textproto` surface (MIME headers, dot *reader*,
  `ReadMIMEHeader`, etc.).
- Adding features beyond what Go's `net/smtp` exposes (it is a frozen package).

## Key design decisions
1. **Async I/O.** Node sockets are async, so client methods return `Promise`s and
   signal failure by throwing instead of Go's returned `error`. `textproto.Error`
   becomes an `Error` subclass carrying `code`/`msg`; its `message` matches Go's
   `fmt.Sprintf("%03d %q", code, msg)` (verified against test expectations like
   `535 "Invalid credentials\nplease see www.example.com"`).
2. **Transport seam.** A `ByteConn { read(): Promise<Buffer|null>; write; close }`
   interface decouples textproto from the socket. Real sockets use a paused/pull
   reader so STARTTLS can hand the underlying socket to `tls.connect` without losing
   buffered bytes; tests inject an in-memory `ByteConn`.
3. **Field visibility.** Go's tests construct `Client` literals and call unexported
   methods (`helo`, `ehlo`) and read unexported fields (`tls`, `didHello`, `ext`).
   The TS `Client` exposes these as public members so the ported tests mirror the Go
   ones closely.
4. **TLS hook.** A module-level hook mirrors Go's `testHookStartTLS` so the TLS tests
   can inject the test root CA.

## Steps
1. Port `textproto` core: `Error`/`ProtocolError`, `goQuote` + minimal `sprintf`
   (`%s`,`%x`,`%d`/`%03d`,`%q`), `Pipeline`/`sequencer`, `Reader.readLine` +
   `ReadResponse`/`parseCodeLine`, `Writer.PrintfLine` + `dotWriter`, `Conn`.
2. Port `auth.go`: `ServerInfo`, `Auth`, `PlainAuth`, `CRAMMD5Auth`.
3. Port `smtp.go`: `Client` + all methods, `Dial`/`NewClient`, `SendMail`,
   `validateLine`, the `dataCloser`.
4. Implement transports: real-socket `ByteConn` (+ TLS upgrade) and in-memory
   `ByteConn`; wire `Dial`/`StartTLS` to them.
5. Port `smtp_test.go` to `smtp.test.ts` (auth tests, basic exchange, HELO/EHLO,
   extensions, NewClient, Hello matrix, SendMail, auth-failed, real-TLS tests).
6. Run `node --test`, fix discrepancies until green.

## Risks & Open Questions
- **Go `bufio.Reader.ReadLine` partial-line-at-EOF** semantics must be replicated
  (a final line without trailing newline is returned, then EOF) — exercised by
  `TestClientAuthTrimSpace`.
- **STARTTLS upgrade** over an already-read socket: relies on the server not sending
  TLS bytes before the client's ClientHello; mitigated by the pull-based reader.
- **Embedded RSA test cert** validity window (1970–~2084) means default time
  verification works in 2026 without Go's `config.Time` epoch hook.
- Dot-encoding/`%q` edge cases must match Go byte-for-byte for the command-trace
  assertions in `TestBasic` / `TestSendMail`.

## Estimated Complexity
High — the client itself is small, but faithfully reproducing the `net/textproto`
behavior, the async transport with STARTTLS upgrade, and the full real-socket/TLS
test suite is substantial.

## Decision (2026-06-19): zero-dep, trimmed scope
The user opted to stay dependency-free (Node builtins only) but cut complexity:
- **Skip the 3 real-TLS integration tests** (`TestNewClientWithTLS`, `TestTLSClient`,
  `TestTLSConnState`) and the embedded cert/key. `StartTLS` / `TLSConnectionState`
  are still implemented in the library for fidelity, just not covered by tests.
- **Collapse the `Pipeline`/sequencer to a no-op** — single-threaded sequential async
  never pipelines concurrently, so behavior is identical.
- Keep the real-socket (non-TLS) `SendMail` tests (`TestSendMail`,
  `TestSendMailWithAuth`) since they exercise `Dial` without TLS complexity.

## Outcome
Done. Delivered:
- `smtp.ts` — single zero-dependency file (Node builtins only: `node:net`,
  `node:tls`, `node:crypto`, `node:buffer`). Ports the textproto subset, `auth.go`,
  and `smtp.go`. Async API that throws instead of returning errors.
- `smtp.test.ts` — port of `smtp_test.go` on the builtin `node:test` runner.
- `package.json` / `tsconfig.json` — dev-only `@types/node` + `typescript` for type
  checking; no runtime deps. `npm test` → `node --test`; `npm run typecheck` → `tsc`.

Result: **16 tests pass, 3 skipped** (the omitted real-TLS tests), `tsc --noEmit`
clean.

Deviations from the original plan:
- Node's strip-only TypeScript mode rejects **parameter properties**
  (`constructor(private x)`); all such constructors were rewritten with explicit
  field declarations + assignments.
- `StartTLS` / `TLSConnectionState` are implemented but untested (TLS tests skipped
  per the trimmed-scope decision). `StartTLS` is still reachable/correct for the
  502-rejection path exercised by `TestHello` case 1.
- The IDE's TS server reports phantom `@types/node` errors; the project `tsc` run
  resolves types correctly (exit 0), so these are false positives.

How to run:
- `npm install` (one-time, dev deps only)
- `npm test` or `node --test`
- To vendor: copy `smtp.ts` alone — it has no third-party imports.
