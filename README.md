# Masqman

Masqman is a Go MySQL proxy that sits between MySQL clients and MySQL Server,
rejects unsafe statements, audits user activity, and masks result fields that
are not explicitly allowed.

The repository contains the completed M1 implementation: local browser login,
explicit one-time MySQL credential issuance, a conservative text-protocol MySQL
proxy, result masking, audit logging, and a Docker Compose MySQL development
environment.

## Requirements

- Go 1.26.x
- Docker with Docker Compose

The module path is:

```text
github.com/dakatsuka/masqman
```

## Repository Guide

- Product behavior: [docs/product-specs/mysql-masking-proxy.md](docs/product-specs/mysql-masking-proxy.md)
- Architecture: [docs/design-docs/initial-architecture.md](docs/design-docs/initial-architecture.md)
- Protocol/parser ADR: [docs/design-docs/adr/0001-mysql-protocol-and-parser-libraries.md](docs/design-docs/adr/0001-mysql-protocol-and-parser-libraries.md)
- M1 execution plan: [docs/exec-plans/completed/m1-implementation.md](docs/exec-plans/completed/m1-implementation.md)
- MySQL protocol notes: [docs/references/mysql-protocol-auth-notes.md](docs/references/mysql-protocol-auth-notes.md)

## Quick Start

Verify the Go project:

```sh
go test ./...
go run ./cmd/masqman -version
```

Start the local MySQL 8.4 development server:

```sh
docker compose up -d mysql
```

Open a MySQL client inside Docker:

```sh
docker compose --profile client run --rm mysql-client
```

Or connect from a local client if one is installed:

```sh
mysql -h 127.0.0.1 -P 33060 -u masqman_proxy -pmasqman_proxy_password app
```

Stop the development database:

```sh
docker compose down
```

Remove the development database volume:

```sh
docker compose down -v
```

## Development Environment

The Compose environment starts:

- `mysql`: MySQL 8.4 exposed on `127.0.0.1:33060`
- `mysql-client`: an optional MySQL client container enabled with the `client`
  profile

The initialization SQL in [dev/mysql/init/001_schema.sql](dev/mysql/init/001_schema.sql)
creates sample `departments` and `employees` tables. The sample data includes
fields used by the masking tests.

Development credentials are intentionally local-only:

```text
database: app
user: masqman_proxy
password: masqman_proxy_password
root password: rootpass
```

## Current CLI

The CLI supports version output and starting Masqman from a validated TOML
configuration:

```sh
go run ./cmd/masqman -version
go run ./cmd/masqman -config ./masqman.toml
```

With a valid config, the process starts the browser authentication listener and
the MySQL proxy listener, sharing one-time credential state between them.

## Validation

Run the current repository checks:

```sh
gofmt -w cmd internal
go test ./...
go tool golangci-lint run ./...
```

Docker-gated protocol and end-to-end tests are available when Docker is
available:

```sh
MASQMAN_RUN_DOCKER_PROTOCOL_TESTS=1 go test ./internal/mysqlproxy -run TestDockerProtocol -count=1
MASQMAN_RUN_DOCKER_PROTOCOL_TESTS=1 go test ./cmd/masqman -run '^TestDockerE2EHTTPIssuedCredentialConnectsToMySQLProxy$' -count=1
```
