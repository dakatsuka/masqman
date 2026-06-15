# Initial Architecture

## Status

Draft

## Context

Masqman is a Go service that mediates access between MySQL clients and MySQL
Server 8.4 or newer. It authenticates users independently from the upstream
database, rejects mutating SQL, forwards allowed read queries, masks result
fields according to origin metadata and configuration, and records audit logs.

The product behavior is described in
`docs/product-specs/mysql-masking-proxy.md`.

Performance is explicitly secondary to correctness, safety, compatibility, and
operability. The architecture can therefore favor simple blocking flows,
conservative buffering, and explicit policy checks over low-latency streaming.

## Goals

- Keep authentication, MySQL protocol handling, SQL policy, masking policy, and
  audit logging as separate modules.
- Define narrow interfaces before implementation so protocol code does not own
  product policy.
- Make the first implementation small enough to validate with Docker Compose and
  real MySQL Server behavior.
- Keep room for future authentication providers without changing how MySQL
  proxy sessions identify users.
- Default to masking or rejecting when field origin or statement safety cannot
  be established.
- Use upstream MySQL privileges as a mandatory defense-in-depth layer, not only
  proxy-side SQL classification.

## Non-Goals

- Building a full SQL firewall or semantic query analyzer in the first design.
- Supporting transparent passthrough for every MySQL command.
- Implementing high-availability credential storage.
- Implementing fine-grained per-user policy in the first milestone.

## Proposed Design

### Process Model

Masqman runs as one Go process with two listeners:

- an HTTP listener for browser authentication and one-time credential issuance;
- a MySQL protocol listener for MySQL client connections.

Both listeners share configuration, credential storage, audit logging, and user
identity services through explicit interfaces.

### Package Boundaries

Initial packages:

- `internal/config`: TOML loading and validation.
- `internal/auth`: authentication provider interfaces, local username/password
  provider, and authenticated user identity.
- `internal/otp`: one-time MySQL credential issuance, verifier lookup,
  rate-limiting, expiry, and consumption. Issuance and verification are separate
  interfaces because HTTP authentication and MySQL protocol authentication are
  different trust boundaries.
- `internal/authhttp`: browser authentication routes and command rendering.
- `internal/mysqlproxy`: MySQL listener, client handshake, upstream connection,
  command loop, and response adaptation.
- `internal/sqlpolicy`: statement classification and rejection decisions.
- `internal/masking`: result metadata classification and value masking.
- `internal/audit`: structured audit event interfaces and initial file logger.

Protocol code may call policy interfaces, but policy packages must not depend on
network listeners.

### Authentication Flow

1. User opens the HTTP authentication UI.
2. `authhttp` starts or completes an authentication flow through an
   `auth.FlowProvider`.
3. On success, `otp.Issuer` creates a short-lived MySQL credential bound to the
   authenticated user identity.
4. The UI renders a copyable MySQL command that prompts for a password and shows
   the one-time password separately.
5. The MySQL listener validates the client credential through the configured
   MySQL authentication plugin and `otp.Verifier`.
6. The MySQL session records the bound authenticated user for audit events.

Future OAuth2 and SAML providers implement the same browser flow boundary and
produce the same user identity type. Local username/password authentication is a
credential verifier behind that boundary, not the shape of all providers.

Successful `POST /login` creates a browser session and redirects to the
credential page. The first one-time MySQL credential is issued only after
`POST /credentials`, so refreshes and login retries cannot accidentally mint
additional credentials.

### MySQL Client Authentication

The first milestone presents `caching_sha2_password` to MySQL clients. Production
configuration requires TLS on the client-to-proxy MySQL listener. RSA password
exchange is out of scope for the first milestone.

The MySQL protocol layer owns plugin-specific challenge and response handling.
It asks `otp.Verifier` for a pending credential by one-time username and receives
only the verifier material needed for the selected authentication plugin. A
credential is consumed only after successful plugin verification and session
acceptance. Failed attempts are audited and rate-limited without consuming the
credential.

For `caching_sha2_password`, the initial implementation uses the full
authentication path over TLS. `PendingCredential.AuthVerifierMaterial` is the
raw one-time password as UTF-8 bytes because `go-mysql-org/go-mysql` validates
full auth through an authentication handler that receives password material. The
OTP store clears that material on successful consume, expiry, and lockout
cleanup.

M1 authentication packet flow:

1. Server sends the initial handshake with `caching_sha2_password`, TLS
   capability, and a random salt.
2. Client upgrades to TLS before password material is exchanged.
3. Client sends the handshake response for the one-time username.
4. Masqman looks up the pending credential and intentionally does not accept a
   fast-auth cache hit.
5. Server sends the `caching_sha2_password` full-auth request.
6. Client sends the clear password over TLS, with the plugin's trailing NUL
   handling.
7. Masqman compares the password to `AuthVerifierMaterial` in constant time,
   consumes the credential, invalidates any library-side cache for that
   username, and returns the authenticated user identity.
8. Masqman sends OK only after audit logging for the accepted session succeeds.

Fast auth is disabled for M1. Because the selected library can populate a
`caching_sha2_password` cache after successful full auth, Masqman must call the
library cache invalidation path after consume and must use unique one-time
usernames so cache hits cannot authenticate a later session. If a later
implementation adds fast-auth success, the verifier contract must explicitly
model cached verifier state and invalidation.

OTP passwords and usernames are generated from a cryptographically secure random
source. The verifier applies rate limits by source address and credential
username before exposing verifier material. Credential-specific lockout lasts
until credential expiry; source address throttling can delay or drop
authentication attempts. Unknown usernames still count against the source
address limiter. Rate-limit state must be safe for concurrent access.

### MySQL Proxy Flow

The first implementation uses `github.com/go-mysql-org/go-mysql` for MySQL
server-side protocol handling and upstream client connections, as recorded in
ADR 0001. Masqman owns policy, audit, session lifecycle, and result rewriting
around that library.

Masqman uses the library's server package for:

- initial handshake and authentication;
- command phase for text-protocol query execution;
- resultset metadata and row packets;
- MySQL-compatible error responses.

For each client session:

1. Accept client connection and authenticate with one-time credentials.
2. Open a dedicated upstream MySQL connection for the client session using the
   configured database account.
3. For each client command, classify it.
4. Reject unsupported or mutating commands with a MySQL-compatible error.
5. Forward allowed read statements upstream.
6. Inspect returned result metadata.
7. Mask disallowed field values.
8. Return the adapted result to the client.
9. Emit audit events for authentication, query decision, and masking summary.

The first milestone uses a 1:1 client-session-to-upstream-connection mapping,
opened after client authentication succeeds and before the first query is
forwarded. Upstream connection establishment, read, and write deadlines are
configurable. If the upstream connection cannot be opened, drops mid-session, or
returns a connection-level error, the proxy emits a generic MySQL-compatible
error where possible, audits the failure, and closes the client session. Pooling
is deferred until session state, `USE`, and setup statements have stricter
ownership rules.

When upstream TLS is enabled, certificate and hostname verification are required.
`skip_verify` behavior is allowed only for development configuration.

M1 enforces resource limits before and during query execution: maximum
concurrent MySQL sessions, maximum query text bytes, maximum result rows, and
maximum encoded resultset bytes. Limit breaches are audited and fail closed.

### Startup And Shutdown

Startup order:

1. Load and validate TOML configuration.
2. Initialize audit logging.
3. Initialize OTP issuer/verifier and rate limiters.
4. Initialize authentication providers and browser session storage.
5. Initialize SQL, setup statement, metadata, and masking policies.
6. Start the HTTP authentication listener.
7. Start the MySQL proxy listener.

If any startup step fails, Masqman closes already-created components before
returning the error.

On graceful shutdown, listeners stop first. Existing MySQL sessions receive a
drain deadline. Sessions that finish before the deadline are audited normally;
remaining sessions are closed and audited as forced closes. Audit sinks are
flushed last.

### Command and Capability Surface

The proxy must advertise only capabilities it implements. The initial command
surface is:

| Item | Initial behavior |
| --- | --- |
| `COM_QUERY` | Supported for policy-approved text statements. |
| `COM_PING` | Supported. |
| `COM_QUIT` | Supported. |
| `COM_INIT_DB` / `USE` | Controlled by schema-selection policy. |
| Prepared statement commands | Rejected. |
| `COM_CHANGE_USER` | Rejected. |
| `LOAD DATA LOCAL INFILE` / `CLIENT_LOCAL_FILES` | Not advertised and rejected. |
| Multi-statements / `CLIENT_MULTI_STATEMENTS` | Not advertised and rejected. |
| Unknown commands | Rejected and audited. |

Prepared statements and binary protocol resultsets are intentionally out of
scope for the first milestone. This keeps masking behavior limited to
text-protocol resultsets until binary value rewriting is explicitly designed.
Multi-result responses are also out of scope. If the upstream returns more than
one resultset for a forwarded statement, Masqman treats that as a policy escape,
audits it, and closes both upstream and client sessions.

Setup statement policy is separate from general query policy. The default
startup allowlist covers only common harmless client initialization statements,
such as `SET NAMES` and `SET character_set_results`. Read-only server variable
probes are classified as `AllowOperationalRead`, not `AllowSetup`. Other `SET`
statements, including `SET GLOBAL` and security-sensitive session changes, are
rejected unless a later design explicitly allows them.

`AllowSetup` statements must not return resultsets. If the upstream returns rows
for an `AllowSetup` decision, Masqman treats the result as a policy violation,
writes an audit event, and closes the client session. `AllowOperationalRead`
statements may return only the built-in non-user-data probe resultsets defined
by `sqlpolicy`; their fields are checked against expression facts, not table
allow rules.

### Error Responses

Masqman maps internal rejection reasons to standard MySQL error packets with
generic messages:

| Case | MySQL error |
| --- | --- |
| Authentication failure | `ER_ACCESS_DENIED_ERROR` 1045 |
| Policy rejection | `ER_SPECIFIC_ACCESS_DENIED_ERROR` 1227 |
| Unsupported command or capability | `ER_NOT_SUPPORTED_YET` 1235 |
| Upstream connection failure | Generic connection error appropriate to phase |

Error messages must not include hidden schema details, allowlist contents,
masked field names, credential values, or sensitive query literals.

### SQL Classification

`sqlpolicy` returns one of:

- `Reject`: statement must not be forwarded.
- `AllowSetup`: statement may be forwarded and must not return a user data
  resultset.
- `AllowOperationalRead`: statement may be forwarded only if it matches a
  built-in M1 startup probe and the returned fields match the expected
  origin-free expressions.
- `AllowRead`: statement may be forwarded and all result fields must be
  evaluated by result policy before being returned.

There is no general "allow and skip masking" decision for user queries in the
first milestone. Any statement that returns a resultset goes through result
policy.

The first classifier can be conservative:

- allow `SELECT` and explicitly configured harmless statements;
- reject obvious mutating and DDL statements;
- reject `SELECT ... INTO OUTFILE`, locking reads, routine calls, and statements
  that require `FILE` or routine privileges;
- reject multiple statements unless explicitly enabled later;
- reject statements that cannot be classified.

The classifier should use a parser or well-scoped tokenizer when practical.
M1 uses the TiDB parser package already pulled by `go-mysql-org/go-mysql` for
statement classification and audit normalization. Ad-hoc prefix checks are
acceptable only inside parser error handling for explicit fail-closed cases.

The configured upstream database account is part of the safety design. It must
have only the minimum schema-level read privileges needed for intended access,
must not have DDL or DML privileges, must not have `FILE`, and must not have
routine execution privileges unless a later accepted design explicitly permits
specific routines. Where practical, sessions should be placed in read-only
transaction mode before forwarding user statements.

Metadata statements are classified separately from data reads. Queries against
`INFORMATION_SCHEMA`, `performance_schema`, `mysql` system schemas, `SHOW
COLUMNS`, `SHOW CREATE`, and `DESCRIBE` are rejected by default unless metadata
policy explicitly allows them.

M1 built-in operational probes are exact parser-normalized patterns:

- `SELECT 1`
- `SELECT NOW()`
- `SELECT DATABASE()`
- `SELECT @@version`
- `SELECT @@version_comment`
- `SELECT @@max_allowed_packet`
- `SELECT @@character_set_client`
- `SELECT @@character_set_connection`
- `SELECT @@character_set_results`
- `SELECT @@collation_connection`

Optional `LIMIT 1` is accepted where MySQL accepts it. Other variable reads are
regular reads and are rejected or masked according to policy.

### Field Origin and Masking

Result policy combines statement-level expression classification with MySQL
column definition metadata. MySQL metadata can include schema, table, original
table, column, and original column names. M1 treats metadata `schema` as the
physical origin schema. Empty schema, original table, or original column
metadata fails closed unless expression policy explicitly allows the field.
`masking.Policy` evaluates each result field in this order:

1. If original schema/original table is allowed as a whole, pass through.
2. If original schema/original table/original column is allowed, pass through.
3. If original column name is globally allowed, pass through.
4. If the field is classified as protocol-required or harmless, pass through.
5. Otherwise mask.

The policy must not match output aliases for allow decisions. Aliases, derived
columns, expressions, empty origin metadata, and ambiguous metadata are
unknown-origin fields. Unknown-origin fields are masked by default unless step 4
applies.

The masking package should preserve resultset shape. First-milestone masking is
text-protocol-only and uses simple type-family placeholders:

- strings and textual types: `***MASKED***`;
- numeric types: `0`;
- date/time types: zero-equivalent textual values for the type family;
- binary/blob types: empty bytes;
- `NULL`: preserved as `NULL`.

Expression policy is explicit and conservative. `sqlpolicy` identifies result
expressions before forwarding when the parser supports it, then passes
expression facts to `masking.Policy` with the returned metadata. The
`Decision.ExpressionContext` slice is ordered by SELECT-list ordinal and must
match the result field order after expansion. `SELECT *` has no per-expression
facts and relies on returned field metadata. If the number of expression facts
does not match the number of returned fields for a non-star projection, Masqman
audits the mismatch and masks all fields whose origin is not physically
allowed.

`SELECT 1`, `SELECT NOW()`, and similar operational probes can be allowlisted.
`COUNT(*)` can be allowlisted. Other unknown-origin aggregates and scalar
functions are masked by default, and concatenating aggregates such as
`GROUP_CONCAT` are rejected or masked by default.

M1 expression and metadata policies are built-in code policy, not
operator-configurable TOML policy. TOML controls physical table/column allow
rules, setup-statement defaults, schema selection, and resource limits. Broader
operator-defined expression and metadata policy is deferred. M1 masking policy
is global; per-user and per-group masking policy is also deferred.

### Audit Logging

Audit events are structured records emitted through an `audit.Logger`
interface. Initial events:

- authentication attempt;
- one-time credential issued;
- MySQL session accepted or rejected;
- query accepted or rejected;
- result masking summary.

Audit records should include timestamps, stable user identifiers, session IDs,
client address, statement decision, and masking counts. They must not include
result values.

Audit logging stores normalized statement shape rather than raw SQL by default.
The first milestone uses parser-backed normalization when a parser is available
for the statement class. Statements that cannot be parsed are logged as a
bounded hash plus rejection metadata, not as raw SQL. The normalizer redacts
string literals, numeric literals, comments, and credential-like tokens before
events are written. One-time passwords, browser passwords, and result values are
never audit fields. File audit sinks create files with owner-only permissions
where supported. Audit write failures fail closed for accepted sessions and
queries.

The file sink supports size-based or time-based rotation. Cryptographic signing
and append-only storage are out of scope for the first milestone, but the
`audit.Logger` interface must allow a stronger sink to replace the file sink
later.

### HTTP Authentication UI

The first milestone uses server-rendered HTML. Required routes are:

- `GET /login`: render the local username/password form.
- `POST /login`: verify local credentials, create a browser session, and
  redirect to the credential page.
- `GET /credentials`: render the credential page for an authenticated browser
  session.
- `POST /credentials`: issue a one-time MySQL credential for an authenticated
  browser session.
- `POST /logout`: destroy the browser session.

State-changing routes require CSRF tokens. Session cookies are `HttpOnly`,
`Secure` in production, and `SameSite=Lax` or stricter. Browser sessions have
configurable idle and absolute lifetimes. Credential issuance is rate-limited
per user and per browser session.

### Configuration

The initial TOML schema is loaded into explicit structs and validated before
listeners start. Plaintext local users are allowed only for the initial
development provider. Upstream passwords may be plaintext in development, but
production configuration must support loading them from environment variables or
external files.

Representative shape:

```toml
[server.mysql]
listen = "127.0.0.1:3307"

[server.http]
listen = "127.0.0.1:8080"
tls = true

[upstream]
addr = "127.0.0.1:3306"
user = "masqman_proxy"
password_file = "/run/secrets/masqman-upstream-password"
database = "app"
tls = "verify_identity"

[credentials]
ttl = "10m"
single_use = true
username_entropy_bits = 96
password_entropy_bits = 192

[rate_limits.mysql_auth]
max_failures_per_credential = 5
max_failures_per_source = 20
window = "10m"

[rate_limits.credential_issuance]
max_per_user = 10
max_per_browser_session = 5
window = "10m"

[sessions.mysql]
idle_timeout = "30m"
max_duration = "8h"
max_concurrent = 100
max_query_bytes = 65536
max_result_rows = 10000
max_result_bytes = 67108864
shutdown_drain_deadline = "30s"

[sessions.browser]
idle_timeout = "30m"
max_duration = "12h"

[[auth.local.users]]
username = "alice"
password_hash = "$argon2id$..."

[setup]
default_startup_allowlist = true
allow_schema_selection = ["app"]

[[masking.allow_tables]]
schema = "app"
table = "departments"

[[masking.allow_columns]]
schema = "app"
table = "employees"
columns = ["id", "department_id", "created_at"]

[masking.allow_column_names]
names = ["id", "created_at", "updated_at"]

[audit]
path = "var/audit.log"
rotation = "daily"
```

## Contracts

```go
// User identifies a human authenticated by Masqman, independent of any
// upstream MySQL account.
type User struct {
    Provider    string
    Subject     string
    DisplayName string
    Groups      []string
}

// Credential is the one-time MySQL credential shown to the authenticated user.
// Password is returned only at issuance time and must not be logged.
type Credential struct {
    ID        string
    Username  string
    Password  string
    ExpiresAt time.Time
}

// PendingCredential exposes verifier material for a not-yet-consumed one-time
// credential. In M1, AuthVerifierMaterial is the raw one-time password as UTF-8
// bytes because TLS-only caching_sha2_password full auth requires password
// material at the selected library boundary.
type PendingCredential struct {
    ID                   string
    Username             string
    ExpiresAt            time.Time
    Locked               bool
    AuthPlugin           string
    AuthVerifierMaterial []byte
}

// FlowProvider completes a browser-side authentication flow and returns a
// Masqman user identity independent of any upstream MySQL account.
// Implementations must be safe for concurrent HTTP requests.
type FlowProvider interface {
    Begin(ctx context.Context, request AuthRequest) (AuthResponse, error)
    Complete(ctx context.Context, request AuthCallback) (User, error)
}

// Issuer creates short-lived MySQL credentials for authenticated browser users.
// Implementations must be safe for concurrent use.
type Issuer interface {
    Issue(ctx context.Context, user User, ttl time.Duration) (Credential, error)
}

// Verifier looks up and consumes one-time credentials during MySQL client
// authentication. Lookup applies source-address and credential-specific rate
// limits before returning verifier material. Implementations must be safe for
// concurrent use.
type Verifier interface {
    Lookup(ctx context.Context, username string, source net.Addr) (PendingCredential, error)
    RecordFailure(ctx context.Context, username string, credentialID string, source net.Addr) error
    Consume(ctx context.Context, credentialID string) (User, error)
}

// Decision describes whether a statement can be forwarded and which result
// processing path must be used.
type Decision struct {
    Kind              DecisionKind
    ExpressionContext []ExpressionContext
}

// FieldMetadata contains the MySQL column definition metadata needed for
// physical-origin masking decisions.
type FieldMetadata struct {
    Schema          string
    Table           string
    OriginalTable   string
    Name            string
    OriginalName    string
    Type            FieldType
    Nullable        bool
}

// ExpressionContext describes the SQL expression that produced a result field
// when the classifier can determine it safely.
type ExpressionContext struct {
    Kind         ExpressionKind
    FunctionName string
    SafeBuiltin  bool
}

// Classifier decides whether a SQL statement may be sent upstream. Returned
// resultsets are never exempt from result policy in the first milestone.
type Classifier interface {
    Classify(ctx context.Context, statement string) (Decision, error)
}

// FieldContext combines a returned field's MySQL metadata with expression facts
// derived from statement classification.
type FieldContext struct {
    Metadata   FieldMetadata
    Expression ExpressionContext
}

// Policy decides whether each result field should pass through or be masked.
type Policy interface {
    DecideField(field FieldContext) FieldDecision
}

// Logger records security-relevant events without storing result values.
// Implementations must be safe for concurrent use.
type Logger interface {
    Log(ctx context.Context, event Event) error
    Close(ctx context.Context) error
}

// Lifecycle is implemented by long-lived components that need deterministic
// cleanup during failed startup or graceful shutdown.
type Lifecycle interface {
    Close(ctx context.Context) error
}
```

Exact package names and struct fields may change during implementation, but
source files must document exported interfaces with block comments.

Long-lived components that own files, goroutines, sockets, or buffers must have
an explicit close path. The exact interface can be `Close(context.Context)`,
`io.Closer`, or a service-level cleanup callback, but shutdown must flush audit
events and release resources deterministically.

## Alternatives Considered

### Authenticate Directly Against MySQL Users

Rejected because requirements state that Masqman authenticates users itself and
connects upstream with a dedicated database account.

### Mask Based Only On Query Text

Rejected because aliases, expressions, joins, and client behavior make query
text alone unreliable. Result metadata is the primary signal, with conservative
fallback masking for unknown origin.

### Reject All Unknown-Origin Fields

Rejected for now because some origin-free values may be required for ordinary
MySQL client behavior or harmless operational queries. Unknown origin defaults
to masking, with narrow pass-through classification for protocol-required or
harmless values.

### Implement All Authentication Providers Immediately

Rejected for the first milestone. The initial local provider validates the
credential issuance contract while provider interfaces keep OAuth2 and SAML
possible later.

## Third-Party Review

An xhigh context-free sub-agent review was completed during initial design. The
review found the direction sound but not implementable as-is until the design
resolved client authentication plugin behavior, protocol command boundaries,
upstream read-only privilege backstops, physical-origin matching, masking
representations, audit redaction, and browser auth extensibility.

Accepted changes from the review:

- choose `caching_sha2_password` with production TLS for first client
  authentication support;
- require least-privilege read-only upstream grants as a defense-in-depth layer;
- define an initial command and capability matrix, rejecting prepared
  statements, local infile, multi-statements, change-user, and unknown commands;
- require allow rules to match original physical metadata, not aliases;
- define first-milestone text-protocol masking placeholders by type family;
- require normalized and redacted audit statement logging with fail-closed audit
  writes;
- split browser authentication flow from local credential verification.

A follow-up review then identified readiness gaps around OTP rate limiting and
entropy, setup statement defaults, generic MySQL error behavior, session
lifecycle, browser session security, OTP interface boundaries, expression
classification, upstream lifecycle, TOML consistency, and metadata query
exposure.

Accepted changes from the follow-up review:

- define OTP entropy, lockout, and source-address throttling requirements;
- ship a narrow default setup statement allowlist while rejecting dangerous
  `SET` statements;
- map rejection classes to standard MySQL errors with generic messages;
- define MySQL session idle timeout, maximum duration, upstream failure
  behavior, and graceful shutdown behavior;
- split OTP contracts into `Issuer` and `Verifier`, define
  `PendingCredential`, and require goroutine-safe implementations;
- add statement expression context to masking policy decisions;
- document server-rendered HTTP auth routes, browser session lifetimes, cookie
  requirements, and CSRF protection;
- require metadata query policy and reject schema-discovery statements by
  default;
- align representative TOML configuration with the product spec.

A final focused review of the ADR and M1 plan found no P0 blockers. It did find
P1 issues around startup probes returning rows, OTP source-address throttling in
the verifier contract, and physical schema origin naming.

Accepted changes from the final review:

- split read-only startup probes into `AllowOperationalRead` so `AllowSetup`
  remains no-result only;
- pass source address into OTP lookup and failure recording so unknown-user
  attempts are rate-limited;
- define the built-in M1 operational probe allowlist;
- clarify that MySQL metadata `schema` is the M1 physical origin schema and
  empty origin metadata fails closed;
- clarify that login redirects to a credential page and credential issuance is
  explicit;
- mark per-user/per-group masking policy as deferred from M1.

## Validation

- Unit tests for TOML validation, credential expiry and consumption, SQL
  classification, masking rule precedence, and audit event construction.
- Integration tests with Docker Compose running MySQL Server 8.4 or newer.
- MySQL client compatibility checks using a containerized client.
- Security-focused tests for rejected mutating statements, comment-prefixed
  statements, multiple statements, unknown-origin fields, and audit redaction.
- Protocol compatibility tests for unsupported command rejection and capability
  negotiation.
- Static analysis and formatting with Go tooling selected during project setup.

## Open Questions

- Should upstream MySQL TLS be required in production when the database is on a
  private network path?
