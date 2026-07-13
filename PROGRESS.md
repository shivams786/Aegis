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
- The gateway does not yet call OPA.
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
- Full crash-recovery worker reconciliation, signed audit roots, and production Merkle manifest generation remain incomplete.

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
