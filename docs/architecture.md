# Architecture

Aegis is split into a data plane, a control plane, and background workers.

The data plane receives REST and MCP requests, authenticates the caller, resolves the tenant and acting identities, validates delegation, validates the target tool schema, calculates risk, evaluates policy, handles approval requirements, reserves budget, checks rate limits, issues scoped credentials, executes the downstream tool, commits or releases budget, and writes audit events.

The control plane owns durable configuration: tools, tool versions, policy bundles, delegation grants, budgets, approval rules, credential templates, and audit exploration. The gateway must be able to serve the data plane without relying on an administrator UI.

Policy bundles are registered durably before rollout. Each tenant can have only one active bundle, activation retires the previous active bundle, and registration/activation both emit redacted outbox events. Simulation runs store baseline and proposed version/hash pairs so replay work can be leased asynchronously without exposing sampled invocation bodies in the control-plane event stream.

Background workers handle tasks that should not be coupled to request latency: outbox delivery, approval expiry, stale reservation cleanup, reconciliation of unknown downstream outcomes, audit-root generation, and policy simulation replay. The current worker drains PostgreSQL outbox rows to NATS, expires stale approvals, releases stale budget reservations, leases persisted unknown-outcome invocations for reconciliation, leases policy simulation replay work, persists redacted simulation summaries, and generates audit roots.

The current development build also includes a deterministic local engine. It is intentionally wired behind the same REST and MCP entry points so local demos can exercise authorization, risk, policy, budgets, approvals, scoped credentials, execution, idempotency, and audit without requiring external credentials. OPA policy evaluation, Redis rate-limit checks, and OpenBao scoped credentials can be selected at runtime with sidecar environment variables; production deployments should continue replacing the remaining local in-memory stores with PostgreSQL-backed repositories and NATS-backed workers behind the same domain contracts.

Gateway API handlers now enqueue redacted invocation outcome events into the PostgreSQL outbox after local-engine state changes. This gives the NATS worker a real producer path for demos and integration work, but production persistence should still move state mutation and outbox insertion into the same PostgreSQL transaction.

## Request Lifecycle

1. Bound and decode the request body.
2. Authenticate the caller and reject malformed, wrong-audience, wrong-issuer, expired, `alg=none`, unknown-key, wrong-token-type, missing-tenant, or malformed-scope tokens.
3. Resolve tenant, subject, agent, client, and delegation identities separately.
4. Validate the delegation grant against tenant, tool, resource, purpose, audience, depth, expiration, and argument constraints.
5. Validate tool arguments against the active versioned JSON Schema and bind the request to the schema hash.
6. Calculate deterministic risk and persist the risk engine version.
7. Evaluate OPA policy through one structured decision contract.
8. If approval is required, persist an approval request and stop before retrieving secrets.
9. Re-evaluate material checks after approval.
10. Reserve budget in PostgreSQL before rate-limited execution.
11. Fetch a just-in-time scoped credential.
12. Execute the downstream tool with idempotency protection.
13. Commit or release budget and append audit events.
14. Write any asynchronous events to the transactional outbox in the same PostgreSQL transaction.

## Transaction Boundaries

PostgreSQL is the source of truth for durable security state. Mutations that require asynchronous processing write outbox rows in the same transaction. Aegis does not use distributed transactions across PostgreSQL, Redis, NATS, OPA, OpenBao, or downstream tools.

Budget reservations and commits use a ledger model with row constraints and optimistic versioning. The invariant is that committed plus reserved spend never exceeds the configured limit.

## Failure Handling

Sensitive or mutating operations fail closed when PostgreSQL, OPA, Redis, the credential broker, or authorization data is unavailable. Downstream timeouts are classified by connector semantics. Irreversible operations are not blindly retried; reconciliation uses idempotency keys or downstream status APIs.

## Credential Flow

Aegis never forwards the user's bearer token to a downstream tool. It obtains or mints a short-lived credential scoped to the exact tenant, tool, action, resource, amount, and invocation after final policy evaluation, budget reservation, and rate-limit checks.

## MCP Proxy Behavior

The MCP gateway will expose Streamable HTTP. `tools/list` filters tools the caller could potentially use, but `tools/call` still re-enters the full invocation pipeline. Aegis never accepts a token issued for a downstream MCP server as authority to access Aegis itself.
