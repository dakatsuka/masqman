# ADR 0001: MySQL Protocol And Parser Libraries

## Status

Accepted

## Context

Masqman must act as a MySQL server to clients and as a MySQL client to the
upstream database. Implementing the full wire protocol, authentication plugins,
result metadata encoding, and client compatibility from scratch is the largest
M1 risk.

The first milestone is intentionally narrow: text protocol, `COM_QUERY`,
`COM_PING`, `COM_QUIT`, controlled `COM_INIT_DB` / `USE`, TLS-only
`caching_sha2_password`, no prepared statements, no local infile, no
multi-statements, and no binary protocol resultsets.

## Decision

Use `github.com/go-mysql-org/go-mysql` for M1 MySQL wire protocol work.

- Use `server` for client-facing MySQL protocol handling.
- Use `client` or its database/sql driver path for the 1:1 upstream connection.
- Configure the client-facing server with `caching_sha2_password` and TLS.
- Implement Masqman's OTP verifier through the library's authentication handler
  boundary.
- Reject unsupported commands in Masqman's handler layer and verify the behavior
  with protocol integration tests.

Use the TiDB parser package already pulled by `go-mysql-org/go-mysql` for M1
statement classification and audit normalization. Parser failures fail closed.

## Consequences

- Masqman avoids a large from-scratch MySQL protocol implementation.
- M1 can focus on policy, audit, masking, and session lifecycle.
- The protocol package must be wrapped carefully because the library supports
  more MySQL surface than Masqman allows.
- `caching_sha2_password` verifier material is initially the raw OTP password,
  held only until credential expiry or successful consumption, because the
  library authentication handler validates against password material. The OTP
  store must clear password material on consume, expiry, and lockout cleanup.
- The library can populate a `caching_sha2_password` cache after full auth.
  Masqman must invalidate that cache after successful OTP consumption and use
  unique one-time usernames so fast auth cannot bypass single-use credentials.
- If raw password retention becomes unacceptable, a later ADR must replace the
  auth provider path with a verifier-hash implementation or another protocol
  library.

## Alternatives Considered

### Vitess `go/mysql`

Vitess has a mature server listener, handler model, and
`caching_sha2_password` implementation, including TLS-only full auth support.
It was not selected for M1 because it brings a much larger dependency surface
and broader Vitess-specific runtime assumptions than Masqman currently needs.

### Dolt `go-mysql-server`

`go-mysql-server` provides a MySQL-compatible SQL engine and server. It is too
large for Masqman's proxy use case because Masqman does not need an embedded SQL
engine.

### From-Scratch Protocol Implementation

Rejected for M1 because authentication and client compatibility would dominate
the milestone and delay validation of the product's masking behavior.

## Validation

- Compile-time integration with Go 1.26.x.
- Docker Compose tests with MySQL Server 8.4 and a containerized `mysql` client.
- Authentication tests for TLS `caching_sha2_password` full auth and failed
  auth lockout.
- Protocol tests for supported commands and rejected prepared statements,
  multi-statements, local infile, change-user, and unknown commands.
- Result metadata tests for physical origin names, aliases, expressions, and
  empty origin metadata.
