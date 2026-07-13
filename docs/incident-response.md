# Incident Response

## Triage

Classify incidents by impact: credential exposure, cross-tenant access, duplicate financial mutation, policy bypass, audit tampering, service outage, or data disclosure.

## Immediate Actions

1. Preserve logs, traces, audit events, and outbox state.
2. Rotate affected credentials in OpenBao or downstream systems.
3. Disable affected tools or policy bundles if continued execution is unsafe.
4. Freeze high-risk approval queues when approver compromise is suspected.
5. Run audit-chain verification for affected tenants.

## Recovery

Use idempotency records and downstream reconciliation APIs to determine whether mutations executed. Never infer success from a timed-out request alone.

## Post-Incident

Add regression tests for the failure mode, update the threat model, document residual risk, and publish a security advisory if users are affected.
