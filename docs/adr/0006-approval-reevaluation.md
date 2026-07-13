# ADR 0006: Approval Re-Evaluation

## Status

Accepted

## Context

Approvals can become stale if policy, delegation, schema, budget, risk, or resource state changes.

## Decision

Approval is not execution authority. After approval, Aegis repeats all material checks before budget reservation, credential issuance, and execution.

## Consequences

This prevents time-of-check/time-of-use vulnerabilities at the cost of extra latency after final approval.
