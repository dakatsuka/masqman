# MySQL Protocol And Authentication Notes

## Source

- URL: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html
- URL: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_command_phase.html
- URL: https://dev.mysql.com/doc/refman/8.4/en/caching-sha2-pluggable-authentication.html
- URL: https://dev.mysql.com/doc/refman/8.4/en/privileges-provided.html
- URL: https://github.com/go-mysql-org/go-mysql
- URL: https://github.com/go-mysql-org/go-mysql/tree/master/server
- Accessed: 2026-06-16

## Summary

MySQL client authentication is plugin-specific. Masqman cannot model MySQL proxy
authentication as receiving a plain username and password from every client.
The proxy must choose and implement a client authentication plugin, advertise
only compatible capabilities, and validate one-time credentials through that
plugin's handshake behavior.

The MySQL command phase contains more than text queries. Capabilities and
commands such as multi-statements, local infile, prepared statements,
change-user, and unknown commands must be intentionally supported or rejected.

`caching_sha2_password` is the default MySQL 8 authentication plugin family and
is the first target for Masqman client authentication. Production deployments
should use TLS for the client-to-proxy MySQL listener. RSA password exchange is
left out of the first milestone.

`caching_sha2_password` includes fast and full authentication paths. Because
Masqman issues short-lived credentials itself, the first milestone should use
the full authentication path over TLS and avoid claiming fast-auth success until
cached verifier behavior is explicitly modeled.

MySQL privileges are an important safety backstop. The upstream account used by
Masqman should be read-only, schema-scoped where possible, and should not have
`FILE`, routine execution, DDL, or DML privileges for the first milestone.

The selected M1 protocol library is `github.com/go-mysql-org/go-mysql`. Its
README describes a pure Go MySQL network protocol library with client and fake
server packages. The server package exposes customizable server configuration,
authentication handlers, `caching_sha2_password`, and TLS support. It also
includes prepared statement and other command handling, so Masqman must reject
unsupported commands explicitly rather than assuming the library surface is
narrow by default.

The selected library writes an in-memory `caching_sha2_password` cache after
successful full auth. Masqman's OTP integration must invalidate that cache after
successful credential consumption and use unique one-time usernames.

Column definition metadata carries both displayed names and physical origin
names when MySQL can provide them. Expressions, aliases, and derived fields can
have empty physical origin fields, so Masqman treats empty or ambiguous origin
metadata as unknown origin.

## Implications

- Do not design OTP verification as if the proxy always receives a plaintext
  password directly from the client.
- Keep the first proxy command surface narrow: text-protocol `COM_QUERY`,
  `COM_PING`, and `COM_QUIT`, with explicit policy for setup statements.
- Reject unsupported capabilities and commands rather than forwarding them.
- Treat upstream grants as part of the security design, not only deployment
  advice.
- Integration tests must verify capability negotiation, `COM_INIT_DB`, rejected
  prepared statements, rejected multi-statements, rejected local infile, and
  empty physical metadata for expression result fields.
