# Progress

## 2026-07-13 - Milestone 0 Cycle 1

Implemented:

- Created monorepo structure for gateway, worker, audit verifier, docs, policies, migrations, deployment, examples, and tests.
- Added Go module targeting Go 1.26 with `chi`, `pgx`, and OpenTelemetry dependencies.
- Implemented gateway configuration loading and validation with redacted database URL handling.
- Implemented PostgreSQL pool setup and dependency-aware readiness.
- Implemented `/live`, `/ready`, `/metrics`, and reserved `/v1` routes with problem-details responses.
- Added structured JSON logging and OpenTelemetry tracer-provider setup.
- Added first PostgreSQL migration with tenant-owned tables, RLS policies, tool registry, delegation grants, invocations, approvals, budgets, ledger entries, outbox events, and audit chain tables.
- Added Docker Compose stack for PostgreSQL, Redis, NATS JetStream, OPA, Keycloak, OpenBao, OpenTelemetry Collector, Prometheus, Grafana, and the gateway.
- Added seed data for Acme, Globex, users, approvers, agents, a delegation grant, tools, a tool version, and a budget.
- Added initial Rego policy and policy tests for default-deny and high-value refund approval behavior.
- Added integration test proving `/ready` succeeds only when PostgreSQL can be opened and pinged.
- Started Milestone 1 domain code with explicit acting identities and delegation grant validation.
- Added tests proving delegated amount, tenant, depth, and unknown argument escalation are denied.
- Added architecture documentation, threat model, security invariants, consistency model, incident response notes, demo script, scaling notes, and ADRs 0001-0010.

Security properties implemented:

- Readiness fails closed when PostgreSQL is unavailable.
- Configuration rejects strict startup without a PostgreSQL URL.
- Database URLs are redacted before logging.
- Tenant-owned tables include `tenant_id`.
- Row-level security is enabled as defense in depth.
- Budget table enforces `reserved_minor + committed_minor <= limit_minor`.
- Delegation validation binds tenant, agent, tool, resource, purpose, audience, depth, expiry, currency, amount, and allowed arguments.
- Rego policy defaults to deny.

Known limitations:

- Go, Docker, Make, OPA, and golangci-lint are not installed in the current execution environment, so tests could not be executed here.
- JWT validation is not implemented yet.
- The gateway does not yet call OPA. Resolved later by the Sidecar Adapter and Audit Verifier Cycle.
- REST invocation normalization and MCP handling are not implemented yet.
- Approvals, budget reservation operations, Redis rate limits, credential issuance, downstream execution, reconciliation, and full audit verification are schema/documentation only at this point.
- CI uses stable action version tags; it is not yet pinned to immutable commit SHAs.

Next milestone:

- Continue Milestone 1: JWT validation, tenant context propagation into PostgreSQL sessions, principal resolution, persistent delegation queries, and security tests for bad issuer/audience/expiry/missing tenant/cross-tenant attempts.

## 2026-07-13 - Milestone 1 Cycle 1

Implemented:

- Added a self-contained JWT validator for RS256 bearer tokens using configured issuer, audience, JWKS source, approved algorithms, required token type, required scopes, and clock skew.
- Added JWKS loading from inline JSON, file, or URL.
- Added explicit rejection paths for `alg=none`, unknown `kid`, unapproved algorithms, bad signatures, wrong issuer, wrong audience, expired tokens, not-yet-active tokens, missing tenant, wrong token type, missing scopes, and malformed scopes.
- Added acting identity extraction that keeps tenant, subject, agent, client, delegation, token type, and scopes separate.
- Added context helpers for authenticated acting identity and tenant ID.
- Protected `/v1/*` and `/mcp` behind JWT middleware when `AEGIS_AUTH_ENABLED=true`.
- Added `/v1/whoami` to return the validated Aegis acting identity.
- Added OAuth protected-resource metadata at `/.well-known/oauth-protected-resource`.
- Added tenant-aware storage helpers, including `WithTenantTx`, `GetTenant`, and `LoadDelegationGrant`.
- Added explicit tenant predicates to storage reads and set `app.tenant_id` inside tenant transactions for RLS defense in depth.
- Added sqlc query contract for delegation grant lookup.
- Updated `.env.example`, Docker Compose, OpenAPI, README, architecture docs, and threat model for JWT authentication.

Security properties implemented:

- Protected routes challenge with `WWW-Authenticate` when auth is enabled.
- JWT validation rejects unsecured, wrong-audience, wrong-issuer, expired, missing-tenant, unknown-key, and malformed-scope tokens.
- Unknown principal types are rejected during acting identity validation.
- Tenant context is explicit in request context and PostgreSQL transaction context.
- Delegation lookup is tenant-scoped and does not load grants without tenant ID.

Tests added:

- JWT success path and identity extraction.
- JWT `alg=none` rejection.
- Unknown `kid` rejection.
- Wrong issuer rejection.
- Wrong audience rejection.
- Expired token rejection.
- Missing tenant rejection.
- Unknown principal type rejection.
- Malformed scope rejection.
- Missing bearer header rejection.
- Protected route challenge behavior.
- Tenant context helper behavior.
- Delegation argument constraint parsing.

Known limitations:

- Go, gofmt, OPA, Docker, and Make are still not installed in this execution environment, so the test suite could not be executed here.
- Only RS256 verification is implemented; ES256 and EdDSA can be added later if needed.
- JWKS refresh and key rotation caching are not implemented yet.
- Keycloak realm custom claim mappers for Aegis-specific tenant, agent, and delegation claims are not fully configured.
- The gateway does not yet resolve principals from PostgreSQL after token validation.
- The gateway still does not evaluate OPA, normalize invocations, register tools through APIs, or execute MCP calls.

Next milestone:

- Continue Milestone 1: persist and resolve principal/agent records from PostgreSQL after JWT validation, enforce authenticated client-to-agent binding, add cross-tenant IDOR security tests against storage/API boundaries, and then move into Milestone 2 tool registry/MCP gateway work.

## 2026-07-13 - Vertical Slice Cycle

Implemented:

- Added deterministic canonical JSON hashing and canonical invocation modeling.
- Added versioned local tool registry with namespace collision protection, tool classifications, schema hashes, and JSON Schema subset validation.
- Added demo tool definitions for payments, CRM, and messaging.
- Added deterministic explainable risk scoring with versioned reason codes.
- Added structured local policy evaluator with allow, deny, approval obligations, credential obligations, redaction obligations, policy hashes, and decision IDs.
- Added policy simulation comparison for approval-to-allow, deny-to-allow, credential-scope widening, and redaction removal.
- Added idempotency store that returns original results and rejects poisoned key reuse.
- Added transactional budget ledger with reservations, commits, releases, and concurrent overspend protection tests.
- Added in-memory rate limiter with retry metadata.
- Added durable approval state machine with multi-approver, group, self-approval, duplicate, expiry, and rejection handling.
- Added scoped credential provider with resource and amount-bound validation.
- Added local demo executor for payments refunds, refund lookup, CRM reads/exports, and messaging sends.
- Added payment idempotency, unknown-outcome simulation, timeout simulation, and reconciliation by idempotency key.
- Added audit hash chain with monotonic tenant sequence numbers and verification.
- Added local transactional outbox model with dead-letter and replay behavior.
- Added shared local invocation engine combining delegation validation, schema validation, risk, policy, approval, budget, rate limit, credentials, execution, idempotency, and audit.
- Wired REST endpoints for invocation submission/status, approval inbox/actions, tool listing, audit events, audit verification, and MCP JSON-RPC `tools/list`/`tools/call`.
- Wired JWT middleware to resolve subject and agent records from PostgreSQL when a database pool is configured.
- Added minimal React/TypeScript admin interface source for approvals, invocations, policy simulation, tool registry, budget status, and audit verification.
- Added PowerShell demo script and k6 load-test scenario.
- Expanded CI workflow with frontend build, vulnerability scanning, secret scanning, container build, and SBOM generation.

Security properties implemented:

- REST and MCP tool calls now share one invocation pipeline.
- Tool schemas are validated before policy.
- Sensitive unknown fields are rejected by schema.
- Tool approvals are bound to schema hash; approvals are denied if the active schema changes before execution.
- Requesters and agent owners cannot approve their own sensitive operations.
- Two distinct finance approvers are required for high-value refunds.
- Idempotency prevents duplicate downstream refunds and detects poisoned replays.
- Budget reservations are concurrency-safe and cannot exceed the configured limit.
- Scoped credentials cannot be reused for a different resource or wider amount.
- Unknown payment outcomes enter `RECONCILIATION_REQUIRED`.
- Audit verification detects event mutation.
- Cross-tenant resource owner mismatches deny without downstream execution.

Tests added:

- Canonical JSON hash stability.
- Tool registry namespace and schema validation.
- Risk scoring.
- Policy approval and cross-tenant decisions.
- Policy simulation dangerous-change detection.
- Idempotency conflict detection.
- Concurrent budget overspend prevention.
- Rate-limit retry metadata.
- Approval self-approval, duplicate, and multi-approver behavior.
- Credential scope rejection.
- Payment idempotency and unknown-outcome reconciliation.
- Audit tamper detection.
- Core end-to-end local engine scenarios for automatic allow, two approvals, idempotent replay, poisoned idempotency, and cross-tenant denial.
- Outbox dead-letter and replay behavior.

Known limitations:

- Go, gofmt, OPA, Docker, Make, k6, and golangci-lint are still not installed in this execution environment, so backend tests, formatting, policy tests, Docker Compose validation, race tests, and load tests could not be executed here.
- The current shared engine uses deterministic in-memory stores for local execution; PostgreSQL persistence exists for the initial schema but is not yet wired for every domain subsystem.
- Redis and NATS are represented in Compose and domain contracts, but the gateway is not yet using Redis/NATS clients at runtime.
- OPA Rego policies exist and local policy behavior mirrors the contract, but the gateway is not yet calling the OPA sidecar.
- OpenBao is in Compose and the credential provider interface exists, but runtime OpenBao credential issuance is not yet wired.
- The admin frontend source exists but dependencies were not installed or built in this environment.
- Keycloak realm mappers for Aegis-specific claims still need complete configuration.
- Connector-specific crash-recovery reconciliation and production KMS-backed Merkle signing remain incomplete.

Next milestone:

- Replace local in-memory engine repositories with PostgreSQL/Redis/NATS/OpenBao/OPA adapters incrementally while preserving the tested domain contracts, then run the full verification suite in an environment with Go, Docker, OPA, k6, and npm dependency installation available.

Verification attempted:

- `npm.cmd --prefix admin install`: passed after network escalation; npm reported 0 vulnerabilities during install.
- `npm.cmd --prefix admin run build`: passed; Vite production build generated `admin/dist`.
- `npm.cmd --prefix admin audit --audit-level=high`: passed after network escalation; found 0 vulnerabilities.
- `go test ./...`: blocked because `go` is not installed/on PATH.
- `go test -race ./...`: blocked because `go` is not installed/on PATH.
- `gofmt`: blocked because `gofmt` is not installed/on PATH.
- `opa test policies`: blocked because `opa` is not installed/on PATH.
- `docker compose -f deploy/docker-compose.yml config`: blocked because `docker` is not installed/on PATH.

## 2026-07-15 - Reconciliation and Audit Root Cycle

Implemented:

- Added idempotency finalization after approval, rejection, and reconciliation so replayed keys return the final terminal result instead of stale pending state.
- Added local reconciliation completion for payment invocations with unknown downstream outcomes.
- Added `POST /v1/invocations/{invocation_id}/reconcile` to drive reconciliation through the gateway.
- Added audit root manifest generation with deterministic root hash and development signature.
- Added `GET /v1/audit/roots` to expose tenant audit root manifests.
- Added engine tests for unknown-outcome reconciliation without duplicate refunds.
- Added engine tests for audit root generation after successful audited events.
- Hardened PostgreSQL identity resolution by scanning subject type as text before casting to the domain principal type.
- Updated OpenAPI for reconciliation and audit root endpoints.

Security properties implemented:

- Unknown payment outcomes can now move from `RECONCILIATION_REQUIRED` to `SUCCEEDED` by querying the deterministic downstream payment ledger by idempotency key.
- Reconciled invocations update idempotency records, so subsequent identical replays return the reconciled result and do not repeat execution.
- Audit roots summarize the tenant event range and are signed by the development signer for tamper-evident root publication flow.

Verification attempted:

- `npm.cmd --prefix admin run build`: passed again on 2026-07-15.
- `Get-Command go`: no Go binary found on PATH.
- `Get-Command docker`: no Docker binary found on PATH.
- `Get-Command opa`: no OPA binary found on PATH.

Known limitations:

- Backend tests for the new reconciliation and audit root paths are written but still could not be executed because Go is unavailable.
- Audit root signatures are deterministic development signatures, not production asymmetric signatures yet.
- Reconciliation is implemented for the local payments demo path; durable lease scheduling is covered later by the Reconciliation Lease Worker Cycle, while PostgreSQL-backed invocation state and connector-specific completion still need hardening.

## 2026-07-15 - Standalone Demo MCP Services Cycle

Implemented:

- Added standalone zero-dependency Node demo MCP services:
  - `examples/payments-mcp/server.js`
  - `examples/crm-mcp/server.js`
  - `examples/messaging-mcp/server.js`
- Payments MCP supports `payments.refund`, `payments.get_refund`, scoped credential validation, idempotent refunds, timeout/unknown-outcome simulation, and reconciliation by idempotency key.
- CRM MCP supports `crm.get_customer`, `crm.search_customers`, `crm.export_customers`, tenant isolation, and restricted-field redaction.
- Messaging MCP supports `messaging.send_email`, fake local sending, recipient-domain restrictions, per-agent rate limiting, and approval-required behavior for large recipient groups.
- Added the three demo MCP services to Docker Compose.
- Added demo MCP service ports to `.env.example`.
- Added `scripts/demo-mcp-services.ps1` and `make demo-mcp-services`.

Verification executed:

- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.
- Live smoke test for Payments MCP `/live` and `payments.refund`: passed.
- Live smoke test for CRM MCP `/live` and `crm.get_customer`: passed.
- Live smoke test for Messaging MCP `/live` and `messaging.send_email`: passed.

Known limitations:

- These standalone services expose a JSON-RPC MCP-like surface suitable for local demos; they are not yet wired as network downstream targets for the Go gateway, which still uses the deterministic in-process executor.
- Docker Compose validation still cannot run because Docker is unavailable in this environment.

## 2026-07-15 - Sidecar Adapter and Audit Verifier Cycle

Implemented:

- Added standard-library OPA Data API policy evaluation adapter with structured input, decision metadata, and fail-closed behavior on sidecar errors.
- Added OpenBao KV-backed scoped credential provider with TTL, resource, action, tenant, tool, and amount validation.
- Added Redis-backed strict rate-limit adapter using raw RESP commands and fail-closed behavior for strict rules.
- Added NATS publisher adapter for outbox event publication.
- Added environment knobs for OPA, OpenBao, NATS, and Redis sidecars.
- Added ADR 0012 documenting the sidecar adapter approach.
- Hardened the core engine so malformed policy approval obligations deny instead of panicking or creating incomplete approval records.
- Added policy fail-closed coverage in the core engine tests.
- Replaced the placeholder audit verifier path with offline audit export verification, tenant filtering, expected-root comparison, and root manifest generation.
- Added audit verifier tests for valid exported chains and tampered exported chains.
- Added `docs/audit-verifier.md` and `make audit-verify-file` for operator usage.
- Added sidecar configuration parsing for OPA, OpenBao, Redis, and NATS.
- Wired the gateway to use the OPA HTTP evaluator when `AEGIS_OPA_URL` is configured.
- Added OPA health checks to `/ready` and the `aegis_ready` metric when OPA is configured.
- Updated the Rego policy bundle to preserve the tenant-resource invariant before allow or approval decisions.
- Added policy tests for cross-tenant OPA denial and OPA adapter tests for pre-validated delegation input and approval TTL parsing.
- Updated Docker Compose to pass sidecar configuration into the gateway and declare startup dependencies on OPA, Redis, NATS, and OpenBao.
- Wired Redis-backed rate-limit checks into the core engine when `AEGIS_REDIS_ADDR` is configured.
- Wired OpenBao-backed scoped credential issuance/validation into the core engine when `AEGIS_OPENBAO_ADDR` and `AEGIS_OPENBAO_TOKEN` are configured.
- Added Redis and OpenBao readiness checks when those sidecars are configured.
- Added core coverage for strict Redis rate-limit fail-closed behavior.

Security properties implemented:

- OPA, Redis, and malformed approval-obligation failures fail closed.
- A configured OPA sidecar must be healthy before the gateway reports ready.
- Configured Redis and OpenBao sidecars must be reachable before the gateway reports ready.
- OPA allow and approval decisions require the invocation tenant to match the resource owner tenant.
- Strict Redis rate limiting denies mutating execution when the distributed limiter is unavailable.
- Exported audit events can be independently verified without trusting the database connection that produced them.
- Audit verifier detects sequence gaps, previous-hash mismatches, event hash mismatches, tenant boundary mistakes, and root hash mismatches.
- Root manifests can be regenerated from verified exported chains for incident response and release evidence.

Verification executed:

- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.
- `where.exe go`: Go is not installed/on PATH.
- `where.exe gofmt`: gofmt is not installed/on PATH.
- `where.exe docker`: Docker is not installed/on PATH.
- `where.exe opa`: OPA is not installed/on PATH.
- `where.exe golangci-lint`: golangci-lint is not installed/on PATH.
- `where.exe k6`: k6 is not installed/on PATH.

Known limitations:

- Backend tests and formatting for the new Go code could not be executed in this environment because Go and gofmt are unavailable.
- Docker Compose, OPA policy tests, linting, race tests, and k6 load tests remain blocked by missing local binaries.
- The sidecar adapters are implemented behind domain contracts; OPA, Redis, and OpenBao are runtime-selectable on the gateway path, and NATS has a worker publisher path for persisted outbox rows.
- OpenBao and NATS adapters are intentionally minimal; production use still needs authentication hardening, pooling, retries, persisted producers for every durable mutation, and integration coverage against the Compose stack.

## 2026-07-15 - NATS Outbox Worker Cycle

Implemented:

- Added `dead_lettered` state to persisted `outbox_events` and tightened the pending index to exclude dead-lettered rows.
- Added tenant-scoped PostgreSQL outbox draining with `FOR UPDATE SKIP LOCKED`, bounded batch size, retry counters, delivery marking, and dead-letter marking.
- Wired `cmd/worker` to publish pending PostgreSQL outbox rows to NATS using the existing NATS publisher adapter.
- Added a dedicated `worker` service to Docker Compose that starts `/aegis-worker` from the shared image.
- Added configurable worker outbox interval, batch size, and max attempts via `AEGIS_WORKER_OUTBOX_*` environment variables.
- Updated architecture, scaling, README, and ADR 0012 notes to reflect the worker/outbox NATS path.

Security and consistency properties implemented:

- Outbox draining respects tenant RLS by processing each tenant inside `WithTenantTx`.
- Publishing is at least once: if a publish succeeds but the database update fails, the row can be retried.
- Failed publishes preserve `last_error`, increment attempts, and dead-letter after the configured retry ceiling.
- Worker scaling uses row locks with `SKIP LOCKED` to avoid duplicate concurrent claims inside a batch.

Verification executed:

- Static file review for worker, storage, migration, and Compose changes completed.
- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.
- `where.exe go`: Go is not installed/on PATH.
- `where.exe docker`: Docker is not installed/on PATH.
- `where.exe opa`: OPA is not installed/on PATH.

Known limitations:

- Go tests, gofmt, Docker Compose validation, and OPA policy tests still cannot run in this environment.
- The worker can drain persisted outbox rows, but the local in-memory gateway engine still does not persist every domain mutation into PostgreSQL outbox rows.
- Stale reservation cleanup and reconciliation leases are covered later by dedicated worker cycles.

## 2026-07-15 - Gateway Outbox Producer Cycle

Implemented:

- Added `Store.EnqueueOutboxEvent` for tenant-scoped PostgreSQL outbox insertion with `ON CONFLICT DO NOTHING`.
- Wired REST invocation submission, MCP tool calls, approval decisions, and reconciliation responses to enqueue redacted invocation outcome events.
- Added deterministic event IDs based on invocation ID, event type, and response update timestamp so idempotent response replays avoid duplicate outbox rows.
- Kept outbox payloads deliberately safe: invocation ID, state, decision, reason codes, approval request ID, and request trace context.
- Updated README and architecture notes to describe the gateway producer path and its current local-engine transaction boundary.

Security and consistency properties implemented:

- Outbox producer writes are tenant-scoped through `WithTenantTx` and RLS.
- Tool outputs and credentials are not included in persisted outbox payloads.
- API response delivery is not blocked after local side effects if outbox enqueue fails; failures are logged for operator visibility.

Verification executed:

- Static file review for API and storage outbox producer changes completed.
- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.

Known limitations:

- Backend tests and gofmt still cannot run because Go is not installed/on PATH.
- Local-engine state changes and PostgreSQL outbox insertion are not yet one atomic transaction; that requires replacing the remaining in-memory repositories with PostgreSQL-backed repositories.

## 2026-07-15 - Approval Expiry Worker Cycle

Implemented:

- Added configurable approval expiry interval via `AEGIS_WORKER_APPROVAL_EXPIRY_INTERVAL`.
- Added PostgreSQL-backed approval expiry that moves expired pending approval requests to `EXPIRED`.
- Added same-transaction `ApprovalExpired` outbox event insertion for expired approvals.
- Updated the worker so approval expiry runs even when NATS outbox publishing is disabled.
- Updated README, architecture docs, `.env.example`, and Docker Compose for the approval expiry worker path.

Security and consistency properties implemented:

- Expiry is tenant-scoped through `WithTenantTx` and RLS.
- Expired approvals emit redacted outbox events without exposing approval reasons or tool payloads.
- Approval expiry is monotonic: only `PENDING` rows whose `expires_at <= now()` are updated.

Verification executed:

- Static file review for worker, config, and storage approval-expiry changes completed.
- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.

Known limitations:

- Backend tests, gofmt, Docker Compose validation, and OPA policy tests still cannot run because the required binaries are unavailable on PATH.
- Approval expiry updates the PostgreSQL approval table; the current local in-memory approval store used by the demo engine remains separate until the approval repository is fully PostgreSQL-backed.

## 2026-07-15 - Audit Root Worker Cycle

Implemented:

- Added signer and signature columns to persisted `audit_roots`.
- Added `audit.VerifySegment` for verifying incremental audit-chain segments against the previous hash.
- Added PostgreSQL-backed audit-root generation for each tenant with new audit events.
- Added worker scheduling for periodic audit-root generation.
- Added configurable audit-root interval and signer via `AEGIS_WORKER_AUDIT_ROOT_INTERVAL` and `AEGIS_WORKER_AUDIT_ROOT_SIGNER`.
- Updated README, architecture docs, `.env.example`, and Docker Compose for the audit-root worker path.

Security and consistency properties implemented:

- Audit-root generation verifies each new segment before writing a root.
- Root rows include signer and deterministic development signature fields.
- Audit-root generation is tenant-scoped through `WithTenantTx` and RLS.
- Root generation is monotonic: it starts after the latest persisted `to_sequence_no` for the tenant.

Verification executed:

- Static file review for audit, storage, worker, config, migration, and docs changes completed.
- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.

Known limitations:

- Backend tests, gofmt, Docker Compose validation, and OPA policy tests still cannot run because the required binaries are unavailable on PATH.
- Audit-root signatures are deterministic development signatures; production still needs KMS-backed signing.

## 2026-07-15 - Budget Reservation Sweep Worker Cycle

Implemented:

- Added configurable budget reservation sweep interval, stale TTL, and batch size via `AEGIS_WORKER_BUDGET_SWEEP_INTERVAL`, `AEGIS_WORKER_BUDGET_RESERVATION_TTL`, and `AEGIS_WORKER_BUDGET_SWEEP_BATCH_SIZE`.
- Added tenant-scoped PostgreSQL stale reservation cleanup that finds old `RESERVE` ledger entries with no matching `COMMIT` or `RELEASE`.
- Released stale reservations by updating the budget row, appending a deterministic `RELEASE` ledger entry, and enqueueing a redacted `BudgetReservationReleased` outbox event in the same transaction.
- Added partial ledger indexes for pending reserve lookup and terminal reservation lookup.
- Wired the worker to run the budget sweeper alongside outbox publishing, approval expiry, and audit-root generation.
- Updated Compose, `.env.example`, README, and architecture docs for the new worker job.

Security and consistency properties implemented:

- Reservation cleanup is tenant-scoped through `WithTenantTx` and RLS.
- The sweeper only releases reservations that have aged past the configured TTL and have no terminal ledger entry.
- Budget rows are updated before the release ledger entry and outbox event are appended in the same PostgreSQL transaction.
- Worker concurrency uses row locks with `FOR UPDATE SKIP LOCKED` on stale reserve rows.

Verification executed:

- Static file review for storage, worker, config, migration, and docs changes completed.
- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.
- `where.exe go`: Go is not installed/on PATH.
- `where.exe gofmt`: gofmt is not installed/on PATH.
- `where.exe docker`: Docker is not installed/on PATH.
- `where.exe opa`: OPA is not installed/on PATH.

Known limitations:

- Backend tests, gofmt, Docker Compose validation, and OPA policy tests still cannot run because the required binaries are unavailable on PATH.
- The sweeper operates on PostgreSQL ledger rows; the current demo engine still uses an in-memory budget ledger until the budget repository is fully PostgreSQL-backed.

## 2026-07-15 - Reconciliation Lease Worker Cycle

Implemented:

- Added durable reconciliation lease columns to `invocations`: attempt count, retry-after timestamp, lease owner, and lease expiry.
- Added a partial pending-reconciliation index for `RECONCILIATION_REQUIRED` invocations.
- Added configurable reconciliation worker interval, batch size, lease duration, retry-after delay, and lease owner via `AEGIS_WORKER_RECONCILIATION_*`.
- Added tenant-scoped PostgreSQL reconciliation leasing with `FOR UPDATE SKIP LOCKED`.
- Enqueued redacted `ReconciliationLeaseClaimed` outbox events for leased unknown-outcome invocations.
- Wired the worker to lease reconciliation work alongside outbox publishing, approval expiry, budget sweeping, and audit-root generation.
- Updated Compose, `.env.example`, README, architecture, scaling, and consistency docs for the reconciliation lease path.

Security and consistency properties implemented:

- Reconciliation leasing is tenant-scoped through `WithTenantTx` and RLS.
- Workers do not retry irreversible operations directly; they claim bounded leases and emit connector-specific reconciliation work.
- Lease attempts are monotonic and retry scheduling is explicit through `reconciliation_not_before`.
- Outbox payloads include invocation ID, state, decision, reason codes, attempt, and lease metadata, but no tool output or credentials.

Verification executed:

- Static file review for storage, worker, config, migration, and docs changes completed.
- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.
- `where.exe go`: Go is not installed/on PATH.
- `where.exe gofmt`: gofmt is not installed/on PATH.
- `where.exe docker`: Docker is not installed/on PATH.
- `where.exe opa`: OPA is not installed/on PATH.

Known limitations:

- Backend tests, gofmt, Docker Compose validation, and OPA policy tests still cannot run because the required binaries are unavailable on PATH.
- The worker leases PostgreSQL invocation rows; the current demo engine still uses in-memory invocation state until the invocation repository is fully PostgreSQL-backed.

## 2026-07-15 - Policy Simulation Lease Worker Cycle

Implemented:

- Added durable `policy_simulation_runs` with baseline/proposed policy versions and hashes, replay scope, state, findings counters, attempts, leases, retry scheduling, and tenant RLS.
- Added a partial pending simulation index for scalable replay leasing.
- Added configurable policy simulation worker interval, batch size, lease duration, retry-after delay, and lease owner via `AEGIS_WORKER_POLICY_SIMULATION_*`.
- Added tenant-scoped PostgreSQL policy simulation leasing with `FOR UPDATE SKIP LOCKED`.
- Enqueued redacted `PolicySimulationLeaseClaimed` outbox events for leased simulation runs.
- Wired the worker to lease policy simulation work alongside outbox publishing, approval expiry, budget sweeping, reconciliation leasing, and audit-root generation.
- Updated Compose, `.env.example`, README, architecture, scaling, and consistency docs for the policy simulation lease path.

Security and consistency properties implemented:

- Policy simulation runs are tenant-scoped through RLS and `WithTenantTx`.
- Workers claim bounded leases and retry using explicit `not_before` timestamps.
- Outbox payloads include simulation ID, baseline/proposed policy metadata, attempt, and lease metadata, but no sampled invocation bodies or credentials.
- The schema rejects no-op simulations where both proposed policy version and hash match the baseline.

Verification executed:

- Static file review for storage, worker, config, migration, and docs changes completed.
- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.
- `where.exe go`: Go is not installed/on PATH.
- `where.exe gofmt`: gofmt is not installed/on PATH.
- `where.exe docker`: Docker is not installed/on PATH.
- `where.exe opa`: OPA is not installed/on PATH.

Known limitations:

- Backend tests, gofmt, Docker Compose validation, and OPA policy tests still cannot run because the required binaries are unavailable on PATH.
- The worker leases simulation runs; full candidate-vs-baseline OPA replay still needs a replay evaluator behind the durable run contract.

## 2026-07-15 - Policy Simulation API Cycle

Implemented:

- Added `POST /v1/policy/simulations` to queue durable policy simulation replay runs.
- Added `GET /v1/policy/simulations` and `GET /v1/policy/simulations/{simulation_id}` for tenant-scoped simulation run inspection.
- Added same-transaction `PolicySimulationRunCreated` outbox event insertion when a simulation run is queued.
- Updated OpenAPI with policy simulation create/list/read endpoints.
- Updated the admin Simulator tab to list queued simulation runs and queue a demo run against Acme.
- Updated README to include policy simulation runs as control-plane state.

Security and consistency properties implemented:

- Request tenant is derived from the authenticated/query tenant context and overrides any tenant value in the JSON body.
- Authenticated requester subject is derived from the token context rather than trusting the request body.
- Simulation creation and outbox insertion happen in one tenant-scoped PostgreSQL transaction.
- Outbox creation payload includes policy versions/hashes and requester metadata, but no sampled invocation bodies or credentials.

Verification executed:

- Static file review for API, storage, OpenAPI, admin UI, and docs changes completed.
- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.
- `where.exe go`: Go is not installed/on PATH.
- `where.exe gofmt`: gofmt is not installed/on PATH.
- `where.exe docker`: Docker is not installed/on PATH.
- `where.exe opa`: OPA is not installed/on PATH.

Known limitations:

- Backend tests, gofmt, Docker Compose validation, and OPA policy tests still cannot run because the required binaries are unavailable on PATH.
- The API queues and reads simulation runs; full candidate-vs-baseline OPA replay still needs a replay evaluator behind the durable run contract.

## 2026-07-15 - Policy Bundle Registry Cycle

Implemented:

- Added durable `policy_bundles` with tenant-scoped version/hash identity, source, status, active flag, optional OPA bundle URL, metadata, creator, activation timestamps, and tenant RLS.
- Enforced one active policy bundle per tenant with a partial unique index.
- Added PostgreSQL storage methods to register, list, read, and activate policy bundles.
- Made policy bundle registration and activation write redacted outbox events in the same tenant-scoped transaction.
- Added `GET /v1/policy/bundles`, `POST /v1/policy/bundles`, `GET /v1/policy/bundles/{bundle_id}`, and `POST /v1/policy/bundles/{bundle_id}/activate`.
- Updated OpenAPI with policy bundle schemas and endpoints.
- Seeded Acme with active `local-policy-v1` bundle metadata and a `candidate-demo` bundle for policy simulation demos.
- Updated the admin Simulator tab to show bundle registry output, register candidate bundles, and queue simulations against the seeded baseline/candidate pair.
- Updated README and architecture, consistency, security-invariant, and demo docs for policy bundle rollout.

Security and consistency properties implemented:

- Request tenant is derived from the authenticated/query tenant context and overrides any tenant value in the JSON body.
- Authenticated creator subject is derived from token context rather than trusting request JSON.
- Activation retires the previous active bundle and activates the selected bundle in one PostgreSQL transaction.
- Bundle registration and activation events include version/hash/status metadata, but no policy source bodies, sampled invocations, or credentials.

Verification executed:

- Static file review for migration, seed data, storage, API, OpenAPI, admin UI, and docs changes completed.
- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.
- `where.exe go`: Go is not installed/on PATH.
- `where.exe gofmt`: gofmt is not installed/on PATH.
- `where.exe docker`: Docker is not installed/on PATH.
- `where.exe opa`: OPA is not installed/on PATH.

Known limitations:

- Backend tests, gofmt, Docker Compose validation, and OPA policy tests still cannot run because the required binaries are unavailable on PATH.
- Policy bundle metadata and simulation leasing are durable; full candidate-vs-baseline OPA replay still needs a replay evaluator behind the durable run contract.

## 2026-07-15 - Policy Simulation Completion Cycle

Implemented:

- Added `CompleteLeasedPolicySimulationRuns` to finalize leased simulation runs owned by a worker.
- Validated baseline/proposed policy hashes against durable `policy_bundles` before completing a run.
- Added bounded deterministic sample counting from recent PostgreSQL invocation rows using `sample_scope` filters for tool, action, resource type, resource ID, and sample limit.
- Persisted terminal simulation summaries into `policy_simulation_runs` with `SUCCEEDED` state, `total_samples`, zero dangerous findings for summary-only replay, cleared leases, and `completed_at`.
- Persisted validation failures into `policy_simulation_runs` with `FAILED` state and redacted findings when referenced bundle hashes are missing.
- Added `PolicySimulationRunCompleted` and `PolicySimulationRunFailed` outbox events.
- Updated the worker to lease and complete simulation runs in the same recurring policy simulation worker loop.
- Updated docs to describe simulation summary completion and the remaining full OPA replay boundary.

Security and consistency properties implemented:

- Simulation completion only processes rows leased by the current worker owner and still inside the lease window.
- Terminal updates and terminal outbox events are written in the same tenant-scoped PostgreSQL transaction.
- Findings and events include versions, hashes, sample counts, and validation status, but no sampled invocation bodies, arguments, credentials, or policy source bodies.
- Sample selection is bounded to prevent unbounded replay work from a single control-plane request.

Verification executed:

- Static file review for storage, worker, and docs changes completed.
- `node --check examples/payments-mcp/server.js`: passed.
- `node --check examples/crm-mcp/server.js`: passed.
- `node --check examples/messaging-mcp/server.js`: passed.
- `npm.cmd --prefix admin run build`: passed.
- `where.exe go`: Go is not installed/on PATH.
- `where.exe gofmt`: gofmt is not installed/on PATH.
- `where.exe docker`: Docker is not installed/on PATH.
- `where.exe opa`: OPA is not installed/on PATH.

Known limitations:

- Backend tests, gofmt, Docker Compose validation, and OPA policy tests still cannot run because the required binaries are unavailable on PATH.
- Policy simulation completion currently writes a durable summary and validates bundle references; full candidate-vs-baseline OPA replay still needs a replay evaluator behind this run-row contract.
