# MySQL Masking Proxy

## Status

Draft

## Problem

Masqman must let internal users inspect production MySQL data while reducing the
risk of exposing or exporting sensitive personal information. The proxy sits
between MySQL clients and a MySQL Server, authenticates users itself, forwards
allowed read queries to the upstream database, and masks result fields that are
not explicitly permitted.

## Goals

- Support MySQL Server 8.4 and newer.
- Let users authenticate through a browser-based authentication server operated
  by Masqman.
- Issue a short-lived one-time MySQL credential after successful user
  authentication.
- Accept MySQL client connections that use the issued one-time credential.
- Connect from Masqman to the upstream MySQL Server with a dedicated database
  account, not with the end user's credential.
- Require the upstream database account to be least-privilege and read-only so
  the database remains a safety backstop if proxy query classification has a
  defect.
- Reject writes and schema mutations at the proxy boundary.
- Mask result fields unless their origin is known and allowed by configuration,
  or unless MySQL protocol compatibility requires passing the value through.
- Record audit logs for authentication events and executed queries.
- Provide a TOML configuration file for initial development.
- Provide a Docker Compose development environment with MySQL Server because the
  local environment may not have a MySQL client installed.

## Non-Goals

- Optimizing query latency or throughput for production-scale traffic.
- Supporting MySQL versions older than 8.4.
- Implementing Google OAuth2, SAML, or centralized user management in the first
  implementation milestone.
- Supporting write traffic through policy controls in the first implementation
  milestone.
- Preventing all possible inference attacks through allowed aggregate results or
  timing behavior.
- Supporting unbounded concurrent sessions, unbounded query text, or unbounded
  resultsets. M1 includes conservative resource limits to protect the proxy and
  upstream database.

## Requirements

### Authentication

- Masqman exposes a browser authentication server on a separate TCP port from
  the MySQL proxy listener.
- The first authentication provider is username and password from TOML
  configuration.
- The authentication design must allow additional providers such as Google
  OAuth2 and SAML without changing the MySQL proxy authentication contract.
- After explicit one-time credential issuance from an authenticated browser
  session, Masqman displays a copyable command in this form and displays the
  one-time password separately:

  ```sh
  mysql -h <proxy-host> -u <one-time-user> -p
  ```

- One-time MySQL credentials expire after a configurable duration.
  Default TTL is 10 minutes.
- One-time credentials are single-use for successful MySQL connection
  establishment. Failed attempts do not consume the credential, but are audited
  and rate-limited.
- One-time credential usernames and passwords are generated with a
  cryptographically secure random source. The username must have at least 96
  bits of entropy, and the password must have at least 192 bits of entropy.
- MySQL client authentication uses `caching_sha2_password` in the first
  milestone. Production deployments require TLS for the client-to-proxy MySQL
  listener because RSA password exchange is out of scope.
- Failed one-time credential attempts are rate-limited by both source address
  and one-time credential username. Defaults are 5 failed attempts per
  credential and 20 failed attempts per source address in a 10 minute window.
  Default limits are configurable. When a credential-specific limit is reached,
  that credential is locked until expiry. When a source-address limit is
  reached, Masqman delays or drops further authentication attempts from that
  source. All rate-limit decisions are audited with generic failure reasons.
- Production deployments require TLS for browser authentication and MySQL
  client-to-proxy authentication. Insecure listeners are development-only.
- The UI must not render a shell command that embeds the password directly in an
  argument by default. It may render `mysql -h <proxy-host> -u <one-time-user>
  -p` and display the one-time password separately for copying.
- Browser authentication sessions have configurable idle and absolute
  lifetimes. Session cookies must be `HttpOnly`, `Secure` in production, and use
  `SameSite=Lax` or stricter. State-changing authentication routes require CSRF
  protection. Defaults are 30 minutes idle lifetime and 12 hours absolute
  lifetime.
- A browser session may issue multiple one-time credentials, but issuance is
  audited and rate-limited per user and per browser session. Defaults are 10
  issued credentials per user and 5 issued credentials per browser session in a
  10 minute window.
- Successful login lands on an authenticated credential page. One-time MySQL
  credentials are issued only by an explicit credential issuance action from
  that page, not automatically by `POST /login`.

### Query Handling

- The proxy rejects `INSERT`, `UPDATE`, `DELETE`, DDL, and other mutating
  statements before forwarding them to the upstream database.
- The initial safe query surface is text-protocol `COM_QUERY` statements that
  are classified as safe reads.
- `SELECT` is not automatically safe. The proxy rejects unsafe read-shaped
  statements such as `SELECT ... INTO OUTFILE`, locking reads, statements that
  invoke routines unless explicitly allowed later, and statements containing
  multiple statements.
- The proxy may allow harmless origin-free statements such as `SELECT NOW()`
  through explicit classification or a whitelist.
- Query rejection must return a MySQL-compatible error to the client. Error
  messages are generic and must not reveal hidden schema details, masking rules,
  allowlist contents, or sensitive literals.
- Policy rejections use a stable Masqman error class mapped to a standard MySQL
  error packet. Authentication failures use `ER_ACCESS_DENIED_ERROR` 1045,
  policy rejections use `ER_SPECIFIC_ACCESS_DENIED_ERROR` 1227, and unsupported
  protocol features use `ER_NOT_SUPPORTED_YET` 1235 unless a more precise
  standard MySQL error is required for client compatibility.
- The upstream MySQL account must not have DDL/DML privileges, `FILE`
  privilege, or routine execution privileges unless a later accepted spec
  explicitly requires them.

### MySQL Protocol Surface

- The first milestone supports the text protocol path needed by common MySQL
  clients: connection handshake, authentication, `COM_QUERY`, `COM_PING`, and
  `COM_QUIT`.
- The proxy advertises only capabilities it implements.
- The proxy rejects unsupported or risky capabilities and commands, including
  multi-statements, local infile, prepared statement commands, `COM_CHANGE_USER`,
  and unknown commands.
- Masqman ships with a narrow default client-startup allowlist. Harmless
  no-result setup statements such as `SET NAMES` and
  `SET character_set_results` are handled separately from read-only operational
  probes that return rows. Operators can disable or extend this allowlist.
- Default read-only startup probes are limited to exact built-in patterns for
  `SELECT 1`, `SELECT NOW()`, `SELECT DATABASE()`, `SELECT @@version`,
  `SELECT @@version_comment`, `SELECT @@max_allowed_packet`,
  `SELECT @@character_set_client`, `SELECT @@character_set_connection`,
  `SELECT @@character_set_results`, and `SELECT @@collation_connection`, with
  optional `LIMIT 1` where MySQL accepts it.
- `USE <schema>` and `COM_INIT_DB` are controlled by explicit schema-selection
  policy, not by the general harmless setup allowlist.
- Other `SET` statements are rejected by default. `SET GLOBAL`, statements that
  change security-sensitive session behavior, and unrecognized setup statements
  are always rejected in the first milestone.
- Multi-result responses are rejected in the first milestone. If an allowed
  statement unexpectedly produces more than one resultset, Masqman closes the
  upstream and client sessions after writing an audit event.

### Session Lifecycle

- Established MySQL sessions have configurable idle timeout and maximum session
  duration. Defaults are 30 minutes idle timeout and 8 hours maximum duration.
- M1 enforces configurable resource limits. Defaults are 100 concurrent MySQL
  sessions, 64 KiB maximum query text, 10,000 rows per resultset, and 64 MiB
  encoded resultset bytes per query. Hitting a limit returns a generic
  MySQL-compatible error, audits the event, and closes the query or session as
  needed to return to a known-safe state.
- One-time credential expiry does not terminate an already accepted session, but
  the maximum session duration still applies.
- If the upstream MySQL connection drops or returns a connection-level error,
  Masqman returns a generic MySQL-compatible error where possible, audits the
  event, and closes the client session.
- On graceful shutdown, Masqman stops accepting new browser and MySQL
  connections, audits the shutdown start, lets in-flight sessions drain until a
  configurable deadline, then closes remaining sessions and audits forced
  closes. Default drain deadline is 30 seconds.

### Result Masking

- The proxy inspects MySQL result metadata to determine field origin where
  possible.
- Fields with unknown origin are masked by default.
- Unknown-origin fields that MySQL clients need for normal operation may pass
  through only when explicitly classified as protocol-required or harmless.
- TOML configuration supports these allow rules:
  - allow all columns from a table;
  - allow selected columns from a table;
  - allow any column with a matching column name.
- Allow rules match physical origin metadata only. Table and column rules use
  the schema, original table, and original column names reported by MySQL
  column-definition metadata. M1 treats the metadata `schema` value as the
  physical origin schema. Output aliases, derived columns, expressions, empty
  origin metadata, and ambiguous metadata are treated as unknown origin unless
  an explicit expression policy allows them.
- Global column-name allow rules are convenience rules and should be treated as
  high-risk. Documentation and validation warnings must prefer table-scoped
  rules for sensitive schemas.
- Non-allowed fields are returned with a masked value while preserving enough
  result shape and type compatibility for common MySQL clients.
- First-milestone masking applies only to text-protocol resultsets. Binary
  protocol resultsets are out of scope because prepared statements are rejected.
- First-milestone masked values are type-family placeholders:
  - character, enum, set, JSON, and spatial values: `***MASKED***`;
  - numeric values: `0`;
  - date and time values: zero-equivalent textual values accepted by MySQL
    clients for that type family;
  - binary/blob values: empty bytes;
  - `NULL` values remain `NULL`.
- Origin-free expressions are handled by explicit expression policy:
  - operational constants and time functions such as `SELECT 1` and
    `SELECT NOW()` may be allowlisted;
  - `COUNT(*)` may be allowlisted because it does not reveal a raw field value;
  - other aggregates and scalar functions are masked by default when origin is
    unknown;
  - concatenating aggregates such as `GROUP_CONCAT` are rejected or masked by
    default.
- M1 expression and metadata policies are built-in, not operator-configurable
  TOML policy. TOML configuration controls table and column allow rules,
  setup-statement defaults, schema selection, and resource limits. Broader
  operator-defined expression and metadata policy is deferred until a later
  accepted spec.
- M1 masking policy is global. Per-user and per-group policy is deferred until a
  later accepted spec.
- Metadata queries such as `INFORMATION_SCHEMA`, `SHOW COLUMNS`, `SHOW CREATE`,
  and `DESCRIBE` can reveal schema structure. M1 rejects them through built-in
  metadata policy. Operator-configurable metadata policy is deferred until a
  later accepted spec.
- Preserving `NULL` while masking non-`NULL` values can reveal nullability at the
  row level. This inference is accepted for the first milestone and documented
  as a known limitation.

### Audit Logging

- Masqman records user authentication attempts and outcomes.
- Masqman records which authenticated user executed each query and when.
- Query audit records must include rejection decisions and masking decisions at
  a level of detail that supports later investigation without storing sensitive
  result values.
- Audit logs store normalized statement shape and decision metadata by default.
  String literals, numeric literals, comments, one-time passwords, browser
  passwords, and result values must not be written to audit logs.
- Audit file outputs must be created with owner-only permissions where the
  operating system supports them.
- If an audit write fails for an accepted MySQL session or query, Masqman fails
  closed by rejecting the operation or closing the session.
- File audit logs are rotated according to configuration. The first milestone
  does not require cryptographic log signing or append-only storage, but audit
  sinks must be replaceable so stronger integrity controls can be added later.

### Configuration

- Initial configuration is TOML.
- TOML may contain initial username/password authentication data.
- TOML contains upstream MySQL connection settings, proxy listener settings,
  authentication listener settings, one-time credential lifetime, masking allow
  rules, setup statement policy, session lifecycle settings, rate-limit
  settings, and audit log settings.
- Upstream database credentials may be read from plaintext TOML in development.
  Production configuration must support reading secrets from environment
  variables or files outside the main configuration document.
- When upstream MySQL TLS is enabled, Masqman validates the upstream server
  certificate and hostname. Skipping verification is development-only.

### Development Environment

- The repository provides Docker Compose wiring for local MySQL Server
  verification.
- Integration tests or manual verification can use Docker Compose because local
  MySQL client tools are not assumed to exist.

## Public Contracts

- CLI and configuration contract: Masqman is configured from a TOML file.
- Browser authentication contract: successful login creates a browser session
  and shows a credential page; explicit credential issuance returns a MySQL
  command and one-time password.
- MySQL proxy contract: clients connect to Masqman with the issued one-time
  credential and receive MySQL-compatible responses.
- Audit contract: authentication and query activity are recorded without storing
  unmasked result values.

## Examples

Example masking rules:

```toml
[setup]
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
```

Example one-time credential flow:

1. User opens `https://masqman.example.test/login`.
2. User signs in with username and password.
3. Masqman redirects to the credential page.
4. User issues a one-time credential from the page.
5. Masqman displays `mysql -h masqman.example.test -u ot_abc123 -p` and shows
   the one-time password separately.
6. User connects through the MySQL client before the credential expires.
7. Masqman authenticates the one-time credential, forwards allowed `SELECT`
   queries, masks disallowed result fields, and writes audit logs.

## Open Questions

- Should upstream MySQL TLS be required in the first production milestone, or
  only strongly recommended when the upstream database is not on a private
  loopback or private network path?
