# Masqman

Masqman is a Go MySQL proxy that will sit between MySQL clients and MySQL
Server, reject unsafe statements, audit user activity, and mask result fields
that are not explicitly allowed.

The project is in the M1 scaffolding phase. The current repository contains the
accepted design documents, a Go module, a minimal CLI entry point, and a Docker
Compose MySQL development environment.

## Requirements

- Go 1.26.x
- Docker with Docker Compose

The planned module path is:

```text
github.com/dakatsuka/masqman
```

## Repository Guide

- Product behavior: [docs/product-specs/mysql-masking-proxy.md](docs/product-specs/mysql-masking-proxy.md)
- Architecture: [docs/design-docs/initial-architecture.md](docs/design-docs/initial-architecture.md)
- Protocol/parser ADR: [docs/design-docs/adr/0001-mysql-protocol-and-parser-libraries.md](docs/design-docs/adr/0001-mysql-protocol-and-parser-libraries.md)
- M1 execution plan: [docs/exec-plans/active/m1-implementation.md](docs/exec-plans/active/m1-implementation.md)
- MySQL protocol notes: [docs/references/mysql-protocol-auth-notes.md](docs/references/mysql-protocol-auth-notes.md)

## Quick Start

Verify the Go scaffold:

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
fields that should eventually exercise masking behavior.

Development credentials are intentionally local-only:

```text
database: app
user: masqman_proxy
password: masqman_proxy_password
root password: rootpass
```

## Current CLI

The CLI currently supports only scaffold verification:

```sh
go run ./cmd/masqman -version
```

Configuration loading, browser authentication, MySQL proxying, masking, and
audit logging are tracked in the M1 execution plan and are not implemented yet.

## Validation

Run the current repository checks:

```sh
gofmt -w cmd internal
go test ./...
go tool golangci-lint run ./...
```

Future M1 work will add Docker Compose integration tests for MySQL protocol
compatibility and masking behavior.
