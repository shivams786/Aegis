# Security Invariants

## Default Deny

Missing, invalid, unavailable, malformed, ambiguous, or stale authorization information results in denial. Sensitive tools fail closed when OPA, PostgreSQL, Redis, the credential broker, or authorization infrastructure is unavailable.

## No Ambient Authority

Agents never inherit all human permissions. Every invocation must carry explicit tenant, subject, agent, client, delegation, tool, action, resource, purpose, audience, expiration, and invocation identifiers.

## Confused-Deputy Protection

Authorization is bound to tenant, subject, agent, client, delegation, tool, action, resource, purpose, audience, argument constraints, and credential scope. Cross-tenant identifiers, audience mismatches, tool substitutions, and delegation escalation are rejected generically.

## No Bearer-Token Forwarding

User bearer tokens are only for authenticating to Aegis. Downstream tools receive separate short-lived scoped credentials.

## Just-In-Time Secret Access

Secrets are not loaded during request validation or approval waiting. Credentials are retrieved only immediately before execution after final policy, budget, and rate-limit checks.

## Approval Is Not Authorization

Approval unlocks a re-check, not execution by itself. After approval, Aegis repeats authentication validity, delegation validity, policy evaluation, tool status, schema hash, budget availability, rate limit, risk score, approval validity, resource ownership, and credential scope checks.

## Separation of Duties

Requesters cannot approve their own sensitive invocations. Rules support required groups, multiple distinct approvers, owner restrictions, expiry, and required reasons.

## Monetary Correctness

Money is represented as integer minor units. Floating-point money is forbidden.

## Idempotent Mutations

Mutating invocations require idempotency keys. The same tenant, tool, action, and key cannot create duplicate side effects. Reusing a key with a different canonical request hash is a conflict.

## Tenant Isolation

Every tenant-owned table includes `tenant_id`. Application queries must explicitly constrain tenants. PostgreSQL row-level security is defense in depth.
