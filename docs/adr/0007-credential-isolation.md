# ADR 0007: Credential Isolation

## Status

Accepted

## Context

Forwarding user bearer tokens to downstream tools creates ambient authority and credential leakage risk.

## Decision

Aegis never forwards user tokens. It retrieves or mints short-lived credentials scoped to the exact downstream operation immediately before execution.

## Consequences

Credential broker availability becomes a hard dependency for mutating tools. The gateway must never log or persist plaintext credentials.
