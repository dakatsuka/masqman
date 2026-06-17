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
- [x] Green: complete parser-backed SQL classification before M1 protocol
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
- Replace the interim `sqlpolicy` scanner classifier with TiDB parser-backed
  statement classification. Parser failures and multiple statements fail
  closed; statement-type dispatch handles `SELECT`, `SET`, and `USE`; AST
  traversal rejects system-schema references, `SELECT ... INTO`, locking reads,
  routine calls, window functions, and aggregates other than source-shaped
  `COUNT(*)`.
- `WITH ... SELECT` is now allowed when the parsed AST is otherwise safe.
  `SHOW`, `DESCRIBE`, system metadata queries, unsafe CTE bodies, and unsupported
  statement classes remain rejected. The tokenizer helper remains only for
  comment/literal normalization, exact setup allowlist checks, built-in
  operational probe matching, executable-comment rejection, and raw source
  validation that distinguishes `COUNT(*)` from identifiers such as
  ``COUNT(`*`)``.
- `sqlpolicy.Decision` now carries parser-derived `ExpressionContext` facts for
  non-star SELECT projections so result masking can later combine statement
  facts with returned MySQL field metadata. `SELECT *` intentionally returns no
  expression facts and relies on physical metadata. Consumers must branch on
  `ExpressionContext.Kind`; `SafeBuiltin` is only an annotation for built-in or
  aggregate expression kinds explicitly safe to pass through, not a replacement
  for the kind.
- Schema selection policy is exact-match for both SQL `USE` and protocol
  `COM_INIT_DB`; M1 does not case-fold configured schema names because MySQL
  deployments can be case-sensitive.
- Pin `github.com/go-mysql-org/go-mysql` v1.15.0 and start `internal/mysqlproxy`
  with compile-time coverage for `server.Handler`, `server.AuthenticationHandler`,
  MySQL error mapping, and `caching_sha2_password` credential setup. This is an
  API boundary spike only; forwarding and containerized client compatibility
  remain pending.
- Enforce `sqlpolicy` decisions before `COM_QUERY` delegation in
  `internal/mysqlproxy`: allowed statements pass to the next protocol handler,
  policy rejections map to `ER_SPECIFIC_ACCESS_DENIED_ERROR`, and unsupported
  protocol surfaces remain `ER_NOT_SUPPORTED_YET`.
- Add the first `internal/mysqlproxy` forwarding boundary: an upstream session
  interface compatible with `*client.Conn`, a `server.Handler` adapter for
  `COM_QUERY` and `COM_INIT_DB`, and a session handler factory that composes
  `sqlpolicy` gating with upstream delegation. Result masking, resource limits,
  audit events, connection ownership, and Docker protocol tests remain pending.
- The forwarding boundary rejects upstream results that carry
  `SERVER_MORE_RESULTS_EXISTS`, closes the upstream session, and returns a
  generic unsupported-protocol MySQL error so later queries cannot reuse a
  desynchronized connection.
- `Config.UpstreamPassword` is the M1 boundary for resolving the dedicated
  upstream database account password. Environment variable references take
  precedence over file references, file references take precedence over inline
  development TOML, configured secret references must resolve to non-empty
  values before production configuration is accepted, and password files trim
  only trailing CR/LF line endings.
- Add an `internal/mysqlproxy` upstream connector boundary before wiring real
  session startup. The connector resolves `config.Config` into a go-mysql client
  connection spec, uses `Config.UpstreamPassword`, builds upstream TLS config
  with TLS 1.2 minimum, optional CA pool from `tls_ca_file`, explicit or
  address-derived server name, and relies on config validation to keep
  `tls_skip_verify` development-only.

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
- `go test ./internal/sqlpolicy` passed on 2026-06-16 after rejecting `FOR
  SHARE` locking reads.
- `go test ./...` passed on 2026-06-16 after rejecting `FOR SHARE` locking
  reads.
- `go tool golangci-lint run ./...` passed on 2026-06-16 with 0 issues after
  rejecting `FOR SHARE` locking reads.
- `go test ./cmd/masqman` passed on 2026-06-16 after wiring CLI `-config`
  validation through `config.Load`.
- `go test ./...` passed on 2026-06-16 after wiring CLI `-config` validation.
- `go tool golangci-lint run ./...` passed on 2026-06-16 with 0 issues after
  wiring CLI `-config` validation.
- `go test ./internal/config` passed on 2026-06-16 after requiring local auth
  users to include username and password.
- `go test ./...` passed on 2026-06-16 after requiring complete local auth
  user configuration.
- `go tool golangci-lint run ./...` passed on 2026-06-16 with 0 issues after
  requiring complete local auth user configuration.
- `go test ./internal/config` passed on 2026-06-16 after rejecting duplicate
  local auth usernames.
- `go test ./...` passed on 2026-06-16 after rejecting duplicate local auth
  usernames.
- `go tool golangci-lint run ./...` passed on 2026-06-16 with 0 issues after
  rejecting duplicate local auth usernames.
- `go test ./internal/mysqlproxy` passed on 2026-06-16 after adding the
  `go-mysql` protocol boundary spike.
- `go test ./...` passed on 2026-06-16 after adding the `go-mysql` protocol
  boundary spike.
- `go tool golangci-lint run ./...` passed on 2026-06-16 with 0 issues after
  adding the `go-mysql` protocol boundary spike.
- `go test ./internal/mysqlproxy` passed on 2026-06-16 after adding the
  `sqlpolicy` gate for query and init-db handling.
- `go test ./...` passed on 2026-06-16 after adding the `sqlpolicy` gate.
- `go tool golangci-lint run ./...` passed on 2026-06-16 with 0 issues after
  adding the `sqlpolicy` gate.
- `go test ./internal/sqlpolicy` passed on 2026-06-17 after replacing the
  interim scanner classifier with TiDB parser-backed classification.
- `go test ./...` passed on 2026-06-17 after parser-backed SQL classification.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  parser-backed SQL classification.
- `go test ./internal/sqlpolicy` passed on 2026-06-17 after code review fixes
  for quoted-star `COUNT`, exact schema matching, and expression facts.
- `go test ./...` passed on 2026-06-17 after parser-backed classifier code
  review fixes.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  parser-backed classifier code review fixes.
- `go test ./internal/sqlpolicy` passed on 2026-06-17 after re-review fix for
  scoped system-variable expression facts.
- `go test ./...` passed on 2026-06-17 after the scoped-variable expression
  facts fix.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  the scoped-variable expression facts fix.
- `go test ./internal/sqlpolicy` passed on 2026-06-17 after adding review-driven
  coverage for routine rejection inside subqueries and CTEs, non-operational
  `DATABASE()` calls, intended `SELECT 1+1` and grouped `COUNT(*)` reads, and
  literal expression context semantics.
- `go test ./...` passed on 2026-06-17 after review-driven classifier test and
  contract-comment updates.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  review-driven classifier test and contract-comment updates.
- `go test ./internal/mysqlproxy` passed on 2026-06-17 after adding the
  upstream forwarding handler and policy-composed session handler factory.
- `go test ./...` passed on 2026-06-17 after the mysqlproxy forwarding handler
  boundary.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  the mysqlproxy forwarding handler boundary.
- `go test ./internal/mysqlproxy` passed on 2026-06-17 after closing upstream
  sessions on unexpected multi-result responses.
- `go test ./internal/config` passed on 2026-06-17 after adding upstream
  password secret resolution.
- `go test ./...` passed on 2026-06-17 after adding upstream password secret
  resolution.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  adding upstream password secret resolution.
- `go test ./internal/mysqlproxy` passed on 2026-06-17 after adding the
  upstream connector boundary and TLS config mapping.
- `go test ./...` passed on 2026-06-17 after adding the upstream connector
  boundary.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  adding the upstream connector boundary.
- Docker Compose integration test with MySQL Server 8.4 or newer.
- Containerized MySQL client compatibility checks.
- Static analysis command selected during Go project setup.

## Completion Notes

Pending.

## Commit

Pending.
