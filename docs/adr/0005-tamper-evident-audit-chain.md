# ADR 0005: Tamper-Evident Audit Chain

## Status

Accepted

## Context

Security decisions must be reconstructable and tampering must be detectable.

## Decision

Append audit events with tenant-local sequence numbers, previous hashes, event hashes, and periodic root manifests.

## Consequences

Historical mutation of audit rows breaks verification at a specific sequence boundary. Audit append throughput becomes an explicit scaling concern.
