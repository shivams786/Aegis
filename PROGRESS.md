# Build Notes

This file is the working build log for Aegis. It keeps the current state easy to review without replaying every implementation cycle.

## Current Feature Inventory

Aegis currently includes:

- Go gateway with liveness, readiness, metrics, REST APIs, and Streamable HTTP MCP.
- JWT validation for RS256 bearer tokens, including issuer, audience, token type, scope, expiry, `alg=none`, and key checks.
- Tenant and acting-identity context for subject, agent, client, delegation, and scopes.
- Delegation validation for tenant, agent, tool, resource, purpose, audience, depth, expiry, currency, amount, and allowed arguments.
- Versioned tool registry with schema hashing and demo tools for refunds, CRM reads/exports, and messaging.
- Deterministic risk scoring with reason codes.
- Local policy evaluator and optional OPA Data API evaluator.
- Approval store with distinct approvers, groups, expiry, rejection, and self-approval protection.
- Budget ledger with reservations, commits, releases, stale-reservation cleanup, and database constraints.
- Local and Redis-backed rate limiting.
- Local and OpenBao-backed scoped credential providers.
- Deterministic demo executor with success, failure, and unknown-outcome paths.
- Idempotency store that rejects poisoned key reuse.
- Hash-chained audit events, root manifests, and an offline audit verifier.
- PostgreSQL migration with tenant-owned tables, indexes, constraints, and row-level security.
- Transactional outbox storage and NATS worker publishing.
- Workers for outbox delivery, approval expiry, stale budget reservations, reconciliation leasing, policy replay, and audit-root generation.
- Policy bundle registry with one active bundle per tenant.
- Metadata-driven policy replay against bounded persisted invocation samples.
- React admin UI for approvals, invocations, policy replay, tools, budget notes, and audit verification.
- Local Compose stack for PostgreSQL, Redis, NATS, OPA, Keycloak, OpenBao, OpenTelemetry Collector, Prometheus, Grafana, gateway, and worker.
- Demo MCP services for payments, CRM, and messaging.

## Demo Story

The seed data uses one coherent local scenario:

- Tenant: `tenant_acme`
- Subject: `user_123`
- Agent: `agent_refund_assistant`
- Customer: `CUST-1042`
- Refund tool: `payments.refund`
- Auto-refund delegation: `dlg_auto_refund`
- Finance-review delegation: `dlg_789`
- Review threshold: Rs 10,000 (`1,000,000` paise)
- Finance approvers: `approver_finance_1`, `approver_finance_2`
- Active policy bundle: `local-policy-v1`
- Candidate replay bundle: `candidate-demo`

The PowerShell demo submits a small refund, submits a high-value refund, applies two finance approvals, and verifies the audit chain. Policy replay compares `local-policy-v1` with `candidate-demo` against a seeded high-value refund sample and reports the approval-to-allow change.

## Recent Repository Pass

The latest pass focused on making policy replay and project wording more coherent:

- Reworked policy replay from a count-only completion path into decision comparison against persisted invocation samples.
- Added bundle metadata controls for approval thresholds, required approvers, risk approval score, forced decisions, redactions, and credential scope.
- Persisted redacted replay findings with invocation ID, tool, action, resource, risk score, baseline/proposed decisions, decision IDs, policy versions, and policy hashes.
- Seeded one replay sample and candidate policy metadata that produces a concrete approval-to-allow finding.
- Added policy tests for threshold-based replay and credential-scope widening.
- Removed stale count-only replay helpers.
- Rewrote the README around the actual current build instead of older milestone language.
- Updated docs that still claimed JWT, OPA, execution, or credential issuance were not implemented.
- Polished admin UI labels, empty states, and JSON formatting.
- Clarified API descriptions that still referenced older reserved milestone behavior.

## Verification Run In This Environment

Passed:

- `node --check examples/payments-mcp/server.js`
- `node --check examples/crm-mcp/server.js`
- `node --check examples/messaging-mcp/server.js`
- `npm.cmd --prefix admin run build`
- `git diff --check`

Blocked because the binaries are not installed or not on `PATH` here:

- `go test ./...`
- `go fmt ./...`
- `go test -race ./...`
- `opa test policies`
- Docker Compose validation

## Remaining Hardening Work

These are the honest remaining gaps before Aegis should be treated as production-ready:

- PostgreSQL is not yet the backing store for every runtime subsystem used by the local engine.
- Policy replay is metadata-driven; executing archived OPA bundle artifacts needs a dedicated adapter.
- Keycloak realm mappers for tenant, agent, delegation, and scope claims need a complete deployment profile.
- Audit-root signatures are deterministic development signatures; production signing should use a KMS-backed signer.
- OpenBao and NATS adapters are intentionally small and need production authentication, pooling, retries, and integration coverage.
- CI and local verification need a machine with Go, OPA, Docker, and the frontend toolchain installed.

## Notes For Reviewers

The repository is intentionally a local security slice, not a finished SaaS product. The most important design choice is that the request path is explicit: authenticate, bind tenant, validate delegation, validate schema, score risk, evaluate policy, handle approvals, reserve budget, check rate limits, issue scoped credentials, execute, and audit. The remaining work should preserve that traceability rather than hiding checks behind broader abstractions.
