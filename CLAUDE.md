# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A TypeScript port of the Go standard library package `net/smtp` (pinned to Go 1.26.4).
The goal is a **faithful** translation that reproduces the original's observable
behavior — the SMTP wire protocol, the `net/textproto` primitives the client relies
on, and the test suite — not a redesign. The reference Go source lives in
`go-go1.26.4/src/net/{smtp,textproto}/` (gitignored); consult it before changing
behavior.

## Commands

```bash
npm install        # one-time, dev-only deps (@types/node, typescript)
npm test           # run the suite: node --test
npm run typecheck  # tsc --noEmit against tsconfig.json
```

Run a single test by name pattern:

```bash
node --test --test-name-pattern="TestAuthFailed"
```

There is no build step — the code runs directly on Node.js >= 24, which strips
TypeScript types natively.

## Hard constraints

- **`smtp.ts` must stay zero-dependency.** It may import only Node builtins
  (`node:net`, `node:tls`, `node:crypto`, `node:buffer`). The file is meant to be
  vendored by copying it alone. `@types/node`/`typescript` are dev-only and never
  ship.
- **No TypeScript parameter properties** (`constructor(private x)`). Node's
  strip-only mode rejects them at runtime with `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`.
  Declare fields explicitly and assign in the constructor body. The same applies to
  other type-directed emit (enums, namespaces, decorators) — keep to syntax that is
  pure type *erasure*.
- Local imports need the explicit `.ts` extension (e.g. `from "./smtp.ts"`), and
  type-only imports must use `import type` so they are erased.

## Architecture

Everything is in one file, `smtp.ts`, layered bottom-up:

1. **textproto layer** — ported from Go's `net/textproto`. `Reader` (buffered line
   reading + `ReadResponse`/`parseCodeLine` multiline code parsing), `Writer`
   (`PrintfLine` + dot-encoding `DotWriter`), the `Pipeline` (collapsed to a no-op
   id counter — single-threaded async never pipelines concurrently), and `Conn` that
   bundles them. `TextprotoError.message` reproduces Go's `fmt.Sprintf("%03d %q", …)`
   format exactly — tests assert on it.
2. **transport seam** — the `ByteConn` interface (`read`/`write`/`close`) decouples
   textproto from the socket. `SocketConn` wraps a Node socket with a **pull-based**
   reader (paused mode) so `StartTLS` can hand the raw socket to `tls.connect`
   without over-consuming bytes. `InMemoryConn` is the test double (Go's `faker`):
   it serves preloaded server bytes and records everything the client writes.
3. **smtp layer** — `Client` and its methods, `Dial`/`NewClient`, `SendMail`,
   `PlainAuth`/`CRAMMD5Auth`, `validateLine`.

### Two conventions that matter

- **Async-throws, not error returns.** Go returns `error`; this port is async and
  throws (`TextprotoError`, `ProtocolError`, or the `EOF` sentinel). Client methods
  return `Promise`s. When porting Go control flow, a returned `err` becomes a thrown
  value, and `if err != nil` becomes `try/catch` or `await assert.rejects`.
- **Go names preserved, including unexported ones.** Methods like `hello`, `helo`,
  `ehlo`, `cmd` and fields like `tls`, `didHello`, `ext` are public here so the
  ported tests can construct `Client` literals and poke internals exactly as
  `smtp_test.go` does. Keep this mirroring when adding code.

### Subtleties to preserve when editing

- `ReadResponse` deliberately keeps the *initial* line's error separate from the
  per-line errors inside the multiline loop (matches Go's variable shadowing); this
  is what lets `expectCode 0` calls return a 5xx code+message without throwing, so
  `Auth` can build the final error itself.
- `helo()` sets `ext = null`, which is why `Extension(...)` reports unsupported after
  a HELO fallback.
- `DotWriter` byte output (leading-dot escaping, `\n`→`\r\n`, trailing `.\r\n`) is
  asserted byte-for-byte by the command-trace tests; don't "simplify" it.

## Tests

`smtp.test.ts` ports `smtp_test.go` onto `node:test` + `node:assert/strict`. The
`crlf()` helper mirrors Go's `strings.Join(strings.Split(s,"\n"),"\r\n")` for the
inline server/client transcripts. The three real-TLS integration tests
(`TestNewClientWithTLS`, `TestTLSClient`, `TestTLSConnState`) are ported against
an in-process TLS server using the embedded localhost cert/key; they drive
`StartTLS`/`TLSConnectionState` end-to-end (the 502-rejection path in `TestHello`
also exercises `StartTLS`). Go's `testHookStartTLS` maps to the exported
`testHooks.startTLS`, which injects the cert as Node's `ca` option. See
`docs/plan-smtp-migration.md` for history.

When a Go test string uses a backtick raw literal containing `\n` (a literal
backslash-n, e.g. the `%q`-escaped error in `TestAuthFailed`), port it with
`String.raw` — a normal template literal would turn `\n` into a real newline.
