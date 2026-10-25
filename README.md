# Cloud Security Compliance Dashboard

A Rust and React platform for read-only multi-cloud security assessment, compliance evidence, remediation guidance, and posture reporting. The approved MVP scope is in [`docs/release-1.md`](docs/release-1.md); implementation progress is tracked in [`TODO.md`](TODO.md).

## Prerequisites

| Tool | Minimum supported version | Purpose |
| --- | --- | --- |
| Rust | 1.88.0 | Edition 2024 API, worker, scanners, and migrations |
| Node.js | 22.12.0 | React dashboard tooling |
| npm | 10.9.0 | Frontend dependency management |
| Docker with Compose | Docker 27 / Compose 2.30 | Local PostgreSQL |
| PostgreSQL | 16 | Runtime database; installed through Docker locally |
| Terraform | 1.8.0 | Later remediation templates; not required for the scaffold |

Use `rustup` to install Rust. You do not need to install PostgreSQL directly on your computer.

## Local setup

```sh
cp .env.example .env
make install
make db-up
make migrate
```

Start the API and dashboard together:

```sh
make dev
```

- API health: <http://127.0.0.1:8080/health>
- Dashboard: <http://127.0.0.1:5173>

Stop PostgreSQL without deleting its named volume:

```sh
make db-down
```

## Checks

```sh
make format
make lint
make test
make build
```

The default database credentials are for loopback-only local development. Production deployments must supply unique credentials through a secret manager, enable TLS and encryption at rest, and keep cloud credentials out of the database and logs.

The initial domain migration creates tenant-scoped organizations, cloud accounts and resources,
normalized checks and findings, scan history, framework mappings, scoring, cost, remediation,
drift, reporting, alert, and audit records. See [`migrations/README.md`](migrations/README.md)
for the raw-response retention and encryption boundary.
