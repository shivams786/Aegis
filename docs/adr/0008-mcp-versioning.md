# ADR 0008: MCP Versioning

## Status

Accepted

## Context

MCP is evolving and Aegis must avoid baking protocol assumptions into authorization logic.

## Decision

Target MCP `2025-11-25` and isolate protocol handling from the canonical invocation pipeline.

## Consequences

New MCP versions can be added by adapting protocol translation while retaining the same security checks.
