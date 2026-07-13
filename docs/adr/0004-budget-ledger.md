# ADR 0004: Budget Ledger Model

## Status

Accepted

## Context

Financial controls must not overspend under concurrency.

## Decision

Represent budgets with integer minor units, reservations, commits, releases, adjustments, and ledger entries in PostgreSQL. Enforce `reserved + committed <= limit` with database constraints and transactional updates.

## Consequences

Budget correctness remains strongly consistent. Redis is not used as the source of truth for financial limits.
