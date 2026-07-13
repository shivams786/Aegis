# ADR 0003: Transactional Outbox

## Status

Accepted

## Context

Aegis must publish durable events without distributed transactions across PostgreSQL and NATS.

## Decision

Any transaction that changes durable state and needs asynchronous publication writes an outbox row in the same PostgreSQL transaction. Workers publish to NATS JetStream and mark rows delivered.

## Consequences

Delivery is at least once. Consumers must be idempotent and replay tooling is required.
