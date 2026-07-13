# Scaling

Gateways are horizontally scalable because durable state lives in PostgreSQL, rate-limit state lives in Redis, and asynchronous delivery uses the outbox. Each gateway should run with a local OPA sidecar to keep policy latency predictable.

PostgreSQL will need tenant-aware indexing, partitioning for audit and invocation tables, and connection pooling before high-volume production use. Hot tenants should be isolated through per-tenant budget rows, rate-limit keys, and audit sequence allocation strategies.

Redis clustering scales rate-limit throughput but strict financial budget correctness remains in PostgreSQL. Redis fallback is never used for financial correctness.

Outbox workers can be scaled by leasing batches. Consumers must be idempotent because delivery is at least once.

At 10x traffic, likely bottlenecks are PostgreSQL connection counts, OPA evaluation latency, audit append throughput, and approval queue reads. At 100x traffic, regional deployment introduces policy distribution lag, cross-region budget contention, and audit-root generation pressure.
