# M1 Implementation

## Status

Completed

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

- [x] Explore: verify `go-mysql-org/go-mysql` server/client APIs in a small
      spike and confirm `caching_sha2_password` full auth over TLS with a
      containerized MySQL client.
- [x] Design review: request sub-agent review for ADR 0001 and this plan;
      incorporate justified feedback.
- [x] Red: write focused tests for config validation, OTP expiry/consume,
      rate limits, SQL classification, masking precedence, audit normalization,
      and HTTP auth sessions.
- [x] Red: write browser route tests for login CSRF, browser session cookies,
      explicit credential issuance, credential command rendering, and logout.
- [x] Green: implement config, OTP, local auth, audit logger, and policy modules.
- [x] Green: implement browser authentication and credential issuance routes in
      `internal/authhttp`.
- [x] Red: write Docker Compose protocol tests for auth, allowed setup
      statements, rejected unsupported commands, forwarded SELECT, masking, and
      metadata query rejection.
- [x] Red: while parser integration remains incomplete, add SQL policy boundary
      coverage for scanner limits: `WITH ... SELECT`, `SHOW`, `DESCRIBE`,
      function allowlist boundaries, and metadata-query rejection.
- [x] Green: complete parser-backed SQL classification before M1 protocol
      forwarding is considered complete.
- [x] Green: implement `internal/mysqlproxy` around `go-mysql-org/go-mysql`.
- [x] Refactor: simplify package boundaries while preserving public contracts.
- [x] Static checks: run Go formatting, tests, and static analysis.
- [x] Code review: request sub-agent review after implementation.
- [x] Re-review: fix findings and repeat review until it passes.

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
  MySQL error mapping, and `caching_sha2_password` credential setup. This began
  as an API boundary spike; later decisions in this plan completed forwarding,
  masking, resource limits, audit wiring, and containerized client compatibility.
- Enforce `sqlpolicy` decisions before `COM_QUERY` delegation in
  `internal/mysqlproxy`: allowed statements pass to the next protocol handler,
  policy rejections map to `ER_SPECIFIC_ACCESS_DENIED_ERROR`, and unsupported
  protocol surfaces remain `ER_NOT_SUPPORTED_YET`.
- Add the first `internal/mysqlproxy` forwarding boundary: an upstream session
  interface compatible with `*client.Conn`, a `server.Handler` adapter for
  `COM_QUERY` and `COM_INIT_DB`, and a session handler factory that composes
  `sqlpolicy` gating with upstream delegation. Later decisions in this plan
  added result masking, resource limits, audit events, connection ownership, and
  Docker protocol tests.
- The forwarding boundary rejects upstream results that carry
  `SERVER_MORE_RESULTS_EXISTS`, closes the upstream session, and returns a
  generic unsupported-protocol MySQL error. Because go-mysql can keep the
  command loop alive after handler errors are converted into error packets, the
  deferred session marks this as a terminal client-session error after this
  point so later commands cannot reuse a desynchronized upstream connection.
  Non-MySQL upstream errors are terminal for the same reason; normal upstream
  `*mysql.MyError` responses remain client-visible query errors and do not
  close the forwarding session.
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
- Add a deferred session handler boundary because go-mysql requires a
  `server.Handler` before the client handshake completes and can call
  `UseDB` for an initial database during that handshake. The deferred handler
  applies schema/query policy immediately, records any pre-auth allowed
  database selection, and replays it to the upstream session only after
  post-auth activation.
- Adapt `otp.Verifier` to go-mysql's `server.AuthenticationHandler` with one
  handler instance per client connection. The handler normalizes the remote
  address to a source host before exposing verifier material, returns
  `caching_sha2_password` credentials to the library, consumes OTP credentials
  only in the auth-success hook, records failures in the auth-failure hook, and
  supports cache invalidation after consume.
- Compose per-client MySQL session state from the OTP auth handler, deferred
  session handler, and upstream connector. On auth success, Masqman connects and
  activates the upstream session before consuming the OTP; upstream connection or
  activation failures reject the client without consuming the credential, and
  consume failures close the just-opened upstream session through the same
  deferred-session close path used by protocol setup cleanup.
- Add a per-connection MySQL protocol handler boundary that builds fresh
  session state from the accepted `net.Conn`, passes the composed
  authentication and command handlers to go-mysql, gives the auth handler the
  accepted connection's remote address for source-rate-limit checks, and closes
  the client connection when go-mysql connection setup fails. The same boundary
  owns the go-mysql command loop after a successful handshake because
  `NewCustomizedConn` only authenticates and initializes the protocol
  connection. Command-loop exit and post-auth setup failures close the activated
  upstream session so M1's 1:1 upstream mapping does not leak connections.
  Terminal session errors reported by the command handler also close the client
  connection after go-mysql has emitted the error packet. Normal client-side
  protocol close, such as `COM_QUIT`, closes the upstream session and ends the
  loop without treating the close as an error.
- Add a MySQL proxy server boundary that owns the TCP listener accept loop,
  dispatches each accepted client connection to a per-client connection handler,
  and waits for started connection handlers before `Serve` returns. The real
  constructor builds a go-mysql server with `caching_sha2_password`; configured
  MySQL listener TLS loads the configured certificate/key, while development
  non-TLS listener mode generates an RSA key for caching SHA-2 full auth. When
  MySQL listener TLS is enabled, Masqman rejects non-TLS client authentication
  before opening the upstream session or consuming the OTP because go-mysql
  advertises TLS support but does not by itself make TLS mandatory.
- Add the first text-protocol result masking boundary in `internal/mysqlproxy`.
  Forwarded resultsets are rewritten before returning to go-mysql's server
  response writer: physical-origin metadata maps to `masking.Policy`, aliases
  are ignored for allow decisions, `NULL` is preserved, and both `RowDatas` and
  `Values` are rebuilt so unit tests and real text-protocol responses observe
  the same masked data. Parser-derived expression facts are carried from the
  policy handler into forwarding so built-in safe expressions such as
  `COUNT(*)` can pass without physical origin metadata. Expression facts permit
  passthrough only when returned field metadata is origin-free; physical-origin
  metadata still goes through masking rules. Streaming resultsets remain
  unsupported because M1 masking is text-resultset rewriting. `AllowSetup`
  decisions must not return resultsets; a resultset on that path is treated as a
  terminal unsupported-protocol violation. Binary string fields reported as
  `STRING` or `VAR_STRING` with binary metadata are masked as empty bytes, not
  as text placeholders.
- Add the first MySQL resource-limit boundary for query text size. The
  per-session command handler rejects `COM_QUERY` strings whose byte length
  exceeds `Config.RateLimits.MaxQueryBytes` before SQL classification or
  upstream forwarding, returning `ER_NET_PACKET_TOO_LARGE`. This limit is
  configured from the validated application config when composing each client
  session. The built-in `SELECT @@max_allowed_packet` operational probe is
  synthesized from the proxy limit instead of forwarded upstream so clients see
  the effective command-size ceiling enforced by Masqman.
- Add a buffered result row-count resource-limit boundary. Forwarded resultsets
  whose row count exceeds `Config.RateLimits.MaxResultRows` are rejected before
  masking or response writing, the upstream session is closed, and the client
  session is marked terminal so a limit breach cannot continue on a potentially
  unsafe result path. For real go-mysql upstream connections, row-limited
  queries use `ExecuteSelectStreaming` and stop at `limit + 1` instead of first
  buffering the full upstream resultset. Streaming resultsets returned by other
  upstream adapters are rejected when row limits are active because M1 cannot
  count them before returning data; this includes both `Result.StreamResult` and
  `Resultset.Streaming` modes.
- Add a text-resultset byte-count resource-limit boundary. Forwarded resultsets
  whose encoded text row data exceeds `Config.RateLimits.MaxResultBytes` are
  rejected before response writing, the upstream session is closed, and the
  client session is marked terminal. Values-only buffered results are normalized
  into encoded `RowDatas` before counting; masking is followed by a second byte
  check because safe output size can grow when placeholders replace short raw
  values. Real go-mysql upstream connections use bounded
  `ExecuteSelectStreaming` when either row or byte result limits are active and
  stop on the first overflow row.
- Add a MySQL listener concurrency boundary for
  `Config.RateLimits.MaxMySQLSessions`. The accept loop acquires a session slot
  before dispatching a client handler, releases it when the handler returns, and
  closes newly accepted TCP connections without protocol startup when all slots
  are occupied.
- Add Docker protocol integration tests gated by
  `MASQMAN_RUN_DOCKER_PROTOCOL_TESTS=1`. The tests use Docker Compose MySQL
  Server as the upstream, a containerized `mysql` client for auth/setup/select
  and metadata rejection paths, and a go-mysql client only for explicit
  `COM_STMT_PREPARE` rejection coverage that the stock CLI cannot trigger
  directly. The compose `mysql-client` service defines `host.docker.internal`
  for host proxy access from the container.
- Add a Docker-gated CLI end-to-end test that starts `cmd/masqman`, authenticates
  through the browser HTTP routes, explicitly issues a one-time credential from
  `/credentials`, then uses the containerized `mysql` client to connect through
  the MySQL proxy with that HTTP-issued credential and verify masked SELECT
  output. This covers shared OTP state between the HTTP listener and MySQL
  listener in the real startup path.
- Add the first MySQL session audit boundary in `internal/mysqlproxy`.
  Successful OTP authentication records an auth event, failed authentication
  records a generic rejected auth event where the protocol hook permits it, and
  auth audit failure rejects the session after closing the activated upstream.
  Query audit is emitted from the policy boundary for allowed, rejected, and
  forwarded-error query paths with normalized statement text, decision,
  authenticated user/source identity, generic error class, and a count of result
  values changed by masking. Query audit failure closes the upstream/session and
  returns a generic MySQL-compatible error.
- Add the first process startup boundary in `cmd/masqman`. After config load and
  validation, the command opens the configured file audit sink, initializes the
  in-memory OTP store, builds the MySQL proxy server with the audit logger, and
  blocks in `Serve` on a configured listener. Startup errors return exit code 1
  after reporting a generic startup failure. `SIGINT` and `SIGTERM` cancel the
  process context, close the MySQL listener so `Serve` can return, and allow the
  audit logger close path to flush and report close errors instead of relying on
  abrupt process termination.
- Add context-aware MySQL server shutdown. `ServeContext` tracks accepted client
  connections, closes the listener and active client connections on context
  cancellation while holding the active-connection lock, rejects just-accepted
  connections when cancellation has already happened, waits for handlers to
  return, and preserves the existing `Serve` API as a background-context
  wrapper. The CLI startup path now uses `ServeContext` so signal cancellation
  can unblock idle or active MySQL client sessions before audit cleanup runs.
- Add the first browser authentication route boundary in `internal/authhttp`.
  `GET /login` renders a local login form with a double-submit CSRF token,
  `POST /login` authenticates local credentials and creates a browser session
  without issuing a one-time MySQL credential, `GET /credentials` renders an
  authenticated credential page, `POST /credentials` validates the session CSRF
  token before issuing and rendering the one-time username/password, and
  `POST /logout` deletes the browser session. The rendered MySQL command keeps
  `-p` separate from the password, while the password is displayed separately.
  Session cookies are `HttpOnly`, `SameSite=Lax`, and use the handler's
  production `Secure` setting.
- Wire the browser authentication listener into `cmd/masqman` startup. The CLI
  now builds a local auth provider, browser session store, shared OTP store, and
  `authhttp` handler, listens on the configured HTTP address, and serves HTTP
  and MySQL listeners under one derived process context. If either listener
  exits unexpectedly, the other is canceled; parent context cancellation remains
  a clean shutdown. The credential page command now includes the configured
  MySQL listener port when one is available, so the default development
  `127.0.0.1:3307` listener renders a usable `mysql -h ... -P ... -u ... -p`
  command. Wildcard MySQL bind hosts defer the rendered host to the HTTP request
  host so remote browser clients do not receive a loopback-only command.

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
- `go test ./internal/mysqlproxy` passed on 2026-06-17 after adding the
  deferred session handler activation boundary.
- `go test ./...` passed on 2026-06-17 after adding the deferred session handler
  activation boundary.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  adding the deferred session handler activation boundary.
- `go test ./internal/mysqlproxy` passed on 2026-06-17 after adding the
  OTP-backed authentication handler adapter.
- `go test ./...` passed on 2026-06-17 after adding the OTP-backed
  authentication handler adapter.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  adding the OTP-backed authentication handler adapter.
- `go test ./internal/mysqlproxy` passed on 2026-06-17 after composing
  auth-success upstream activation with deferred session state.
- `go test ./...` passed on 2026-06-17 after composing auth-success upstream
  activation with deferred session state.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  composing auth-success upstream activation with deferred session state.
- `go test ./internal/mysqlproxy` passed on 2026-06-17 after adding the
  per-connection MySQL protocol handler boundary.
- `go test ./...` passed on 2026-06-17 after adding the per-connection MySQL
  protocol handler boundary.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  adding the per-connection MySQL protocol handler boundary.
- `go test ./internal/mysqlproxy` passed on 2026-06-17 after fixing review
  findings for terminal handler errors, non-MySQL upstream error cleanup, and
  OTP consume-failure cleanup.
- `go test ./...` passed on 2026-06-17 after fixing terminal handler errors,
  non-MySQL upstream error cleanup, and OTP consume-failure cleanup.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  fixing terminal handler errors, non-MySQL upstream error cleanup, and OTP
  consume-failure cleanup paths.
- `go test ./internal/mysqlproxy` passed on 2026-06-17 after adding the MySQL
  listener server boundary.
- `go test ./...` passed on 2026-06-17 after adding the MySQL listener server
  boundary.
- `go tool golangci-lint run ./...` passed on 2026-06-17 with 0 issues after
  adding the MySQL listener server boundary.
- `GOCACHE=/tmp/masqman-go-build go test ./internal/mysqlproxy` passed on
  2026-06-18 after adding text-protocol result masking at the forwarding
  boundary.
- `GOCACHE=/tmp/masqman-go-build go test ./...` passed on 2026-06-18 after
  wiring configured masking policy into MySQL client sessions.
- `GOCACHE=/tmp/masqman-go-build go tool golangci-lint run ./...` passed on
  2026-06-18 with 0 issues after text-protocol result masking.
- `GOCACHE=/tmp/masqman-go-build go test ./internal/mysqlproxy` passed on
  2026-06-18 after review fixes for streaming-result rejection, setup-resultset
  rejection, and origin-free operational-read passthrough checks.
- `GOCACHE=/tmp/masqman-go-build go test ./...` passed on 2026-06-18 after
  result masking review fixes.
- `GOCACHE=/tmp/masqman-go-build go tool golangci-lint run ./...` passed on
  2026-06-18 with 0 issues after result masking review fixes.
- `GOCACHE=/tmp/masqman-go-build go test ./internal/mysqlproxy` passed on
  2026-06-18 after re-review fixes for binary string masking and direct
  origin-free operational literal coverage.
- `GOCACHE=/tmp/masqman-go-build go test ./...` passed on 2026-06-18 after
  re-review fixes for result masking.
- `GOCACHE=/tmp/masqman-go-build go tool golangci-lint run ./...` passed on
  2026-06-18 with 0 issues after result masking re-review fixes.
- `GOCACHE=/tmp/masqman-go-build go test ./internal/mysqlproxy` passed on
  2026-06-18 after enforcing `MaxQueryBytes` before SQL classification and
  upstream forwarding.
- `GOCACHE=/tmp/masqman-go-build go test ./internal/mysqlproxy` passed on
  2026-06-18 after review fixes for exact query-size boundary coverage,
  oversized unsafe-query precedence, and synthesized `@@max_allowed_packet`
  responses from `MaxQueryBytes`.
- `GOCACHE=/tmp/masqman-go-build go test ./internal/mysqlproxy` passed on
  2026-06-18 after enforcing `MaxResultRows` before masking and response
  writing, including boundary, config-wiring, and streaming rejection coverage.
- `GOCACHE=/tmp/masqman-go-build go test ./internal/mysqlproxy` passed on
  2026-06-18 after review fixes that route row-limited upstream reads through
  bounded `ExecuteSelectStreaming` and stop at `limit + 1`.
- `GOCACHE=/tmp/masqman-go-build go test ./internal/mysqlproxy` passed on
  2026-06-18 after re-review fixes for `Resultset.Streaming` rejection and
  masked bounded-streaming positive-path coverage.
- `go test ./internal/authhttp` passed on 2026-06-20 after adding browser login,
  credential issuance, CSRF, cookie, and logout route coverage.
- `go test ./...` passed on 2026-06-20 after adding browser authentication
  routes.
- `go tool golangci-lint run ./...` passed on 2026-06-20 with 0 issues after
  adding browser authentication routes.
- `go test ./cmd/masqman ./internal/authhttp` passed on 2026-06-20 after wiring
  the HTTP authentication listener into CLI startup.
- `go test ./...` passed on 2026-06-20 after wiring the HTTP authentication
  listener.
- `go test -race ./cmd/masqman ./internal/authhttp` passed on 2026-06-20 after
  wiring concurrent HTTP and MySQL listener startup.
- `go tool golangci-lint run ./...` passed on 2026-06-20 with 0 issues after
  wiring the HTTP authentication listener.
- `GOCACHE=/tmp/masqman-go-build go test ./internal/mysqlproxy` passed on
  2026-06-18 after re-review fixes to avoid `MaxResultRows`-sized
  preallocation and to close rejected streaming results.
- `go test ./internal/mysqlproxy` passed on 2026-06-20 after enforcing
  `MaxResultBytes` for buffered, values-only, masked, and bounded-streaming
  result paths.
- `go test ./internal/mysqlproxy` passed on 2026-06-20 after enforcing
  `MaxMySQLSessions` in the MySQL listener accept loop.
- `go test ./...` passed on 2026-06-20 after result byte and MySQL session
  concurrency limit work.
- `go test ./internal/mysqlproxy` passed on 2026-06-20 after adding gated
  Docker protocol integration tests; Docker execution was not run because
  `MASQMAN_RUN_DOCKER_PROTOCOL_TESTS` was unset.
- `MASQMAN_RUN_DOCKER_PROTOCOL_TESTS=1 go test ./internal/mysqlproxy -run
  TestDockerProtocol -count=1` passed on 2026-06-20 against Docker Compose
  MySQL Server and the containerized MySQL client.
- `MASQMAN_RUN_DOCKER_PROTOCOL_TESTS=1 go test ./cmd/masqman -run
  '^TestDockerE2EHTTPIssuedCredentialConnectsToMySQLProxy$' -count=1` passed on
  2026-06-20 after adding CLI HTTP-to-MySQL credential flow coverage.
- `go test ./...` passed on 2026-06-20 after adding the Docker-gated CLI E2E
  test.
- `go test -race ./cmd/masqman` passed on 2026-06-20 after adding the
  Docker-gated CLI E2E test.
- `go tool golangci-lint run ./...` passed on 2026-06-20 with 0 issues after
  adding the Docker-gated CLI E2E test.
- `go test ./internal/mysqlproxy` passed on 2026-06-20 after adding auth and
  query audit wiring to MySQL proxy sessions.
- `go test ./...` passed on 2026-06-20 after MySQL proxy audit wiring.
- `go tool golangci-lint run ./...` passed on 2026-06-20 with 0 issues after
  MySQL proxy audit wiring.
- `go test ./cmd/masqman` passed on 2026-06-20 after wiring CLI startup to the
  audit logger, OTP store, and MySQL proxy server.
- `go test ./...` passed on 2026-06-20 after CLI startup wiring.
- `go tool golangci-lint run ./...` passed on 2026-06-20 with 0 issues after
  CLI startup wiring.
- `go test ./cmd/masqman` passed on 2026-06-20 after adding context/signal
  cancellation for startup shutdown and audit cleanup coverage.
- `go test ./...` passed on 2026-06-20 after context/signal shutdown wiring.
- `go tool golangci-lint run ./...` passed on 2026-06-20 with 0 issues after
  context/signal shutdown wiring.
- `go test ./internal/mysqlproxy -run
  TestServerContextCancellationClosesActiveConnections` passed on 2026-06-20
  after adding context-aware active MySQL connection shutdown.
- `go test ./internal/mysqlproxy -run TestServerContextCancellation` passed on
  2026-06-20 after closing active connections under lock and rejecting
  just-accepted connections after cancellation.
- `go test ./cmd/masqman ./internal/mysqlproxy` passed on 2026-06-20 after
  wiring CLI shutdown through `ServeContext`.
- `go test ./...` passed on 2026-06-20 after context-aware MySQL server
  shutdown.
- `go tool golangci-lint run ./...` passed on 2026-06-20 with 0 issues after
  context-aware MySQL server shutdown.

## Completion Notes

M1 now has the first usable Masqman path:

- local browser login with CSRF-protected server-rendered routes;
- explicit one-time MySQL credential issuance from `/credentials`;
- MySQL protocol authentication with single-use credentials;
- read-only SQL classification, setup statement handling, and metadata-query
  rejection;
- upstream forwarding with text-resultset masking;
- conservative query/result/session resource limits;
- structured file audit logging for authentication and query paths;
- CLI startup for shared HTTP and MySQL listeners with context-aware shutdown;
- Docker-gated protocol and HTTP-to-MySQL end-to-end coverage.

Deferred follow-up work remains intentionally outside M1: OAuth2/SAML, source
IP binding for one-time credentials, operator-configurable expression and
metadata policy, per-user/per-group masking policy, and the product/spec open
question about requiring upstream MySQL TLS in the first production milestone.

## Commit

Implemented across the M1 commit series. This completed plan was moved out of
`active/` after the implementation and verification work was finished.
