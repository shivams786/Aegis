# Consistency Model

Budget correctness is strongly consistent in PostgreSQL. Reservations, commits, releases, and adjustments are ledger entries protected by constraints so reserved plus committed spend cannot exceed the limit.

Events use at-least-once delivery through a transactional outbox. Consumers must be idempotent because an event can be published more than once after crashes or retries.

Policy bundle distribution is eventually consistent. Policy decisions persist the policy version and schema hash so historical decisions can be reconstructed and simulated.

Invocation state transitions are monotonic and validated by domain code. Invalid transitions must fail closed and append an audit event.

Unknown downstream outcomes are represented explicitly as `RECONCILIATION_REQUIRED`. Aegis does not blindly retry irreversible operations after a timeout or crash.
