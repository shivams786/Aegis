# ADR 0010: Unknown Execution Outcomes

## Status

Accepted

## Context

Downstream tools can time out after applying a side effect, and workers can crash between execution and durable success recording.

## Decision

Represent ambiguous mutations as `RECONCILIATION_REQUIRED`. Use idempotency keys and downstream status APIs to reconcile before retrying.

## Consequences

Irreversible operations are not blindly retried. Connectors must declare their unknown-outcome semantics.
