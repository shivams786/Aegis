# ADR 0002: OPA Sidecar Policy Evaluation

## Status

Accepted

## Context

Authorization policy needs to be explainable, testable, and independently reviewable.

## Decision

Run OPA as a local sidecar and use one structured decision contract. Decisions include `allow`, `decision`, `reason_codes`, optional approval requirements, and obligations.

## Consequences

Local sidecars reduce network latency and blast radius. Gateway code must fail closed for sensitive operations when OPA is unavailable.
