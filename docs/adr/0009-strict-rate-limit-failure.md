# ADR 0009: Strict Rate-Limit Failure Behavior

## Status

Accepted

## Context

Rate-limit infrastructure can fail, but some operations are too risky for local fallback.

## Decision

Strict and mutating tools fail closed when Redis is unavailable. Low-risk read-only tools may use bounded local fallback only when configured.

## Consequences

Availability is intentionally traded for safety on financial and sensitive operations.
