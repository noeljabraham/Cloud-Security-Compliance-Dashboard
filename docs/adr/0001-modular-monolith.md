# ADR 0001: Start as a modular monolith

- Status: accepted
- Date: 2026-10-25

## Decision

Build one Rust workspace containing an HTTP API, a background worker, shared domain code, and provider scanners. Deploy the API and worker separately when needed, while keeping one repository and one PostgreSQL database. The React dashboard remains a separate build in the same repository.

## Why

The modules need the same domain model, authorization rules, scan lifecycle, and database. A workspace keeps those boundaries explicit without adding network protocols, distributed transactions, or separate deployment pipelines before scale requires them.

## Consequences

- API, worker, domain, and scanner code can be tested and versioned together.
- Worker load can scale separately from the API using the same build artifact set.
- Module boundaries must be preserved in code; the shared database is not permission to bypass them.
- Split a module into a service only when measured scaling, reliability, or team-ownership needs justify the operational cost.

