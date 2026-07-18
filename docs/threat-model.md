# Threat Model

This model uses STRIDE categories and assumes a hostile multi-tenant environment.

## Threat Actors

- Malicious end user
- Compromised agent
- Prompt-injected agent
- Malicious MCP server
- Compromised approver
- Insider administrator
- Cross-tenant attacker
- Network attacker
- Database attacker
- Stolen credential attacker

## Spoofing

Threats include forged JWTs, `alg=none`, wrong issuer, wrong audience, unknown key IDs, expired tokens, malformed scopes, missing tenants, and agents claiming a different owner or tenant. Mitigations are strict JWT validation, configured issuer and audience, required token type, separate subject and agent identities, and delegation grants bound to client, agent, tenant, tool, resource, purpose, and audience.

## Tampering

Threats include modified invocation arguments, stale approvals after schema or policy changes, mutated audit records, idempotency poisoning, and direct database edits. Mitigations are canonical request hashes, schema hashes, approval re-evaluation, unique idempotency constraints, hash-chained audit events, Merkle roots, and migration-reviewed constraints.

## Repudiation

Threats include requesters denying an invocation, approvers denying an approval, or workers losing event context. Mitigations are immutable audit events, request IDs, trace IDs, actor separation, outbox events with trace context, and append-only approval decisions.

## Information Disclosure

Threats include cross-tenant resource probing, secret leakage in logs, full argument persistence, and downstream credential reuse. Mitigations are generic cross-tenant denials, redacted arguments, scoped credentials, OpenBao secret retrieval only at execution time, and log fields limited to safe reason codes.

## Denial of Service

Threats include oversized payloads, deeply nested JSON, policy-engine overload, Redis outage, and expensive downstream calls. Mitigations are bounded bodies, strict timeouts, readiness checks, Redis-backed rate limits, circuit breakers, and fail-closed behavior for strict tools.

## Elevation of Privilege

Threats include delegation widening, requester self-approval, privileged users authorizing agent actions without delegation, tool substitution, and approval replay. Mitigations are explicit delegation validation, separation-of-duties rules, tool/schema hash binding, approval expiry, approval re-evaluation, and tests proving an agent cannot widen a grant.

## Residual Risk

The local build now exercises the main authorization path: JWT validation, delegation checks, policy decisions, approvals, budgets, scoped credentials, execution, idempotency, audit, outbox delivery, and policy replay. The remaining production risks are narrower but still important:

- Some runtime state still uses deterministic in-memory stores for the local demo.
- Policy replay compares bundle metadata; replaying archived OPA bundle artifacts needs a dedicated adapter.
- Development audit-root signatures are deterministic and should move to KMS-backed signing before external publication.
- The Keycloak realm export still needs a complete deployment profile for Aegis-specific claims.
- The Compose stack uses development credentials and is not suitable for shared or public environments.
