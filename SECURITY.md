# Security Policy

## Supported Status

Aegis is in pre-release development. Security issues should still be reported privately because the project is security-sensitive by design.

## Reporting a Vulnerability

Open a private security advisory or contact the maintainers through the configured project security channel. Do not file public issues for vulnerabilities that could enable cross-tenant access, credential exposure, policy bypass, approval bypass, duplicate financial side effects, audit tampering, or denial-of-service.

## Handling Rules

- Do not include real secrets, real customer data, or production tokens in reports.
- Include reproduction steps, affected commit, expected behavior, and observed behavior.
- Maintainers should acknowledge reports within two business days once a public project channel exists.

## Security Baseline

Aegis defaults to denial when authorization material is missing, malformed, ambiguous, or unavailable. Sensitive operations must fail closed when policy, credentials, budgets, or core authorization infrastructure are unavailable.
