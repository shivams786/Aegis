# Consistency Model

Budget correctness is strongly consistent in PostgreSQL. Reservations, commits, releases, and adjustments are ledger entries protected by constraints so reserved plus committed spend cannot exceed the limit. A background sweeper can release old reserve entries only when no terminal commit or release entry exists for the same invocation and budget.

Events use at-least-once delivery through a transactional outbox. Consumers must be idempotent because an event can be published more than once after crashes or retries.

Policy bundle distribution is eventually consistent. Policy decisions persist the policy version and schema hash so historical decisions can be reconstructed and simulated. The policy bundle registry is strongly consistent inside one tenant: a partial unique index allows only one active bundle, and activation retires any previous active bundle in the same PostgreSQL transaction that emits the activation outbox event.

Policy replay is leased through PostgreSQL rather than performed inline with bundle publication. Workers claim bounded leases, publish redacted replay events, validate referenced bundle hashes, choose a bounded recent-invocation sample by scope, compare baseline and proposed decisions from bundle metadata, and record terminal findings back to the durable run row. Replaying archived OPA bundle artifacts remains a later policy-engine adapter behind the same run row contract.

Invocation state transitions are monotonic and validated by domain code. Invalid transitions must fail closed and append an audit event.

Unknown downstream outcomes are represented explicitly as `RECONCILIATION_REQUIRED`. Aegis does not blindly retry irreversible operations after a timeout or crash. Workers lease reconciliation rows with bounded lease windows and retry-after timestamps, then publish redacted reconciliation-request events for connector-specific reconcilers.
