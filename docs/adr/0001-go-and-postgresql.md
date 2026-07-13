# ADR 0001: Go and PostgreSQL

## Status

Accepted

## Context

Aegis needs predictable latency, straightforward deployment, strong concurrency primitives, and durable transactional security state.

## Decision

Use Go for backend services and PostgreSQL as the system of record. Use `pgx` for runtime access and `sqlc` for generated query code.

## Consequences

Go keeps gateway binaries small and operationally simple. PostgreSQL provides transactions, constraints, row-level security, and a strong base for budgets, approvals, idempotency, outbox, and audit logs.
