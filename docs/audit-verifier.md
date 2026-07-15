# Audit Verifier

The audit verifier checks exported Aegis audit events without trusting the database that produced them. It recomputes each event hash, checks the previous-hash chain, and generates a root manifest for the verified event range.

## Offline Verification

Export one tenant's audit events as either a JSON array:

```json
[
  {
    "tenant_id": "tenant_acme",
    "sequence_no": 1,
    "event_id": "aud_tenant_acme_1",
    "event_type": "INVOCATION_SUCCEEDED",
    "actor_type": "agent",
    "actor_id": "agent_refund_assistant",
    "redacted_payload": {},
    "event_hash": "sha256:...",
    "occurred_at": "2026-07-15T12:00:00Z"
  }
]
```

Or as an object:

```json
{
  "tenant_id": "tenant_acme",
  "events": []
}
```

Then run:

```sh
go run ./cmd/audit-verifier -file ./audit-events.json -tenant tenant_acme -root-out ./audit-root.json
```

The command exits non-zero when a sequence number, previous hash, event payload, event hash, tenant boundary, or expected root hash does not match.

## Root Comparison

Use `-expect-root` during incident response or release verification when a previously published root hash exists:

```sh
go run ./cmd/audit-verifier -file ./audit-events.json -tenant tenant_acme -expect-root sha256:published_root
```

The generated root signature is still a development signature. Production signing should move to a KMS-backed asymmetric signer before external publication.

## Connectivity Check

When no `-file` is provided, the verifier checks PostgreSQL connectivity using the same environment configuration as the gateway:

```sh
go run ./cmd/audit-verifier
```
