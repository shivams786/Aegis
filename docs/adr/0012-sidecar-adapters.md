# ADR 0012: Standard-Library Sidecar Adapters

## Status

Accepted

## Context

The deterministic local engine is useful for development, but production deployments need adapters for OPA, OpenBao, Redis, and NATS without weakening domain contracts.

## Decision

Add standard-library adapters for OPA Data API evaluation, OpenBao KV-scoped credential storage, Redis strict rate-limit checks, and NATS event publication. These adapters sit behind the same policy, credential, rate-limit, and outbox interfaces used by the local engine. OPA, Redis, and OpenBao are selectable on the gateway request path through environment configuration; NATS is wired through the worker/outbox publication path.

## Consequences

The project can evolve from local deterministic execution to sidecar-backed execution incrementally. The adapters are deliberately small and conservative; production hardening still needs authentication, pooling, retries, observability, persisted outbox producers for every durable mutation, and complete integration tests against Docker Compose.
