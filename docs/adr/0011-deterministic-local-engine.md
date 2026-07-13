# ADR 0011: Deterministic Local Engine

## Status

Accepted

## Context

Aegis needs executable demos and security tests even when external development credentials or local services are unavailable. The production architecture still requires PostgreSQL, Redis, NATS, OPA, and OpenBao.

## Decision

Implement a deterministic local engine behind the same REST and MCP entry points. The engine uses in-memory repositories for tools, policy, budgets, approvals, credentials, execution, idempotency, and audit while preserving the same domain contracts expected from production adapters.

## Consequences

Local demos and unit tests can exercise the complete security flow without external dependencies. Production hardening must replace in-memory adapters with durable PostgreSQL, Redis, NATS, OPA, and OpenBao implementations without weakening the domain invariants.
