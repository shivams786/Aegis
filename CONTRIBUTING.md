# Contributing

Contributions should preserve Aegis security invariants and avoid weakening authorization for convenience.

Before opening a change:

```sh
go fmt ./...
go test ./...
go test -race ./...
opa test policies
npm --prefix admin run build
```

For security-sensitive changes, include tests for the failure path as well as the success path. Do not introduce plaintext credentials into source, logs, traces, fixtures, or snapshots.

All tenant-owned database changes must include `tenant_id` and explicit tenant predicates in queries. Row-level security is defense in depth, not the primary tenant-isolation mechanism.
