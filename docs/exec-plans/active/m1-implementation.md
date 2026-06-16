# M1 Implementation

## Status

Active

## Objective

Implement the first usable Masqman milestone: browser login with local users,
one-time MySQL credentials, a conservative MySQL text-protocol proxy,
read-only query forwarding, result masking, and structured audit logging.

## Context

- Product spec: `docs/product-specs/mysql-masking-proxy.md`
- Design doc: `docs/design-docs/initial-architecture.md`
- ADR: `docs/design-docs/adr/0001-mysql-protocol-and-parser-libraries.md`
- Reference: `docs/references/mysql-protocol-auth-notes.md`

## Clarifications

- MySQL protocol library: `github.com/go-mysql-org/go-mysql`.
- SQL parser: TiDB parser package pulled by `go-mysql-org/go-mysql`.
- Browser routes: `/login`, `/credentials`, and `/logout`.
- M1 expression and metadata policy: built-in code policy, not TOML.
- OTP source/IP binding: deferred; TTL, single-use credentials, entropy, and
  rate limiting are the M1 controls.
- M1 masking policy is global; per-user and per-group masking policy is
  deferred.
- Resource limits are in scope for M1: concurrent MySQL sessions, query bytes,
  result rows, and result bytes.

## Contract First

- `auth.FlowProvider`
- `otp.Issuer`
- `otp.Verifier`
- `sqlpolicy.Classifier`
- `masking.Policy`
- `audit.Logger`
- Configuration structs for listeners, upstream, credentials, sessions,
  setup policy, masking rules, rate limits, and audit sink.

## Steps

- [ ] Explore: verify `go-mysql-org/go-mysql` server/client APIs in a small
      spike and confirm `caching_sha2_password` full auth over TLS with a
      containerized MySQL client.
- [x] Design review: request sub-agent review for ADR 0001 and this plan;
      incorporate justified feedback.
- [x] Red: write focused tests for config validation, OTP expiry/consume,
      rate limits, SQL classification, masking precedence, audit normalization,
      and HTTP auth sessions.
- [x] Green: implement config, OTP, local auth, audit logger, and policy modules.
- [ ] Red: write Docker Compose protocol tests for auth, allowed setup
      statements, rejected unsupported commands, forwarded SELECT, masking, and
      metadata query rejection.
- [x] Red: while parser integration remains incomplete, add SQL policy boundary
      coverage for scanner limits: `WITH ... SELECT`, `SHOW`, `DESCRIBE`,
      function allowlist boundaries, and metadata-query rejection.
- [ ] Green: complete parser-backed SQL classification before M1 protocol
      forwarding is considered complete.
- [ ] Green: implement `internal/mysqlproxy` around `go-mysql-org/go-mysql`.
- [ ] Refactor: simplify package boundaries while preserving public contracts.
- [ ] Static checks: run Go formatting, tests, and static analysis.
- [ ] Code review: request sub-agent review after implementation.
- [ ] Re-review: fix findings and repeat review until it passes.

## Decisions

- Use 1:1 client session to upstream connection mapping in M1.
- Reject prepared statements and binary protocol in M1.
- Reject multi-result responses in M1.
- Fail closed on audit write failure.
- Keep expression and metadata policies built-in for M1.
- Treat read-only startup probes as `AllowOperationalRead`, not `AllowSetup`.
- Issue OTPs from `POST /credentials`, not automatically from login.
- Implement the first `sqlpolicy` package as a conservative built-in scanner
  while the `go-mysql-org/go-mysql` and TiDB parser spike remains incomplete.
  The scanner is comment-aware and quote-aware for the covered M1 tests, but
  parser-backed classification remains required before protocol forwarding is
  complete.
- Known scanner limits are intentionally fail-closed for M1 foundation work:
  `WITH ... SELECT`, `SHOW`, and `DESCRIBE` are rejected; only `count()` is
  allowlisted as a function-shaped read; broader expression and metadata
  handling must be parser-backed before M1 protocol forwarding is complete.
  Boundary tests for the interim scanner are regression coverage, not a
  replacement for ADR 0001's parser-backed classification requirement.

## Verification

- `go test ./...` passed on 2026-06-16 for config, OTP, local auth, audit,
  masking, SQL policy, and browser session modules.
- `go tool golangci-lint run ./...` passed on 2026-06-16 with 0 issues.
- `go test ./internal/sqlpolicy` passed on 2026-06-16 after adding scanner
  boundary coverage for `WITH`, `SHOW`, `DESCRIBE`, metadata-query rejection,
  and `COUNT(*)`-only function allowlisting.
- `go test ./...` passed on 2026-06-16 after SQL policy scanner boundary
  coverage.
- `go tool golangci-lint run ./...` passed on 2026-06-16 with 0 issues after
  SQL policy scanner boundary coverage.
- Docker Compose integration test with MySQL Server 8.4 or newer.
- Containerized MySQL client compatibility checks.
- Static analysis command selected during Go project setup.

## Completion Notes

Pending.

## Commit

Pending.
