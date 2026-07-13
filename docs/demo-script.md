# Demo Script

## Milestone 0 Demo

1. Start the stack:

   ```sh
   make bootstrap
   make up
   make migrate
   make seed
   ```

2. Confirm liveness:

   ```sh
   curl -fsS http://localhost:8080/live
   ```

3. Confirm dependency-aware readiness:

   ```sh
   curl -fsS http://localhost:8080/ready
   ```

4. View Prometheus metrics:

   ```sh
   curl -fsS http://localhost:8080/metrics
   ```

5. Open Grafana at `http://localhost:3000` and view the Aegis dashboard.

The local engine now supports executable coverage for automatic allow, human approval, self-approval blocking, cross-tenant denial, idempotent replay, idempotency poisoning, strict budget reservations, messaging rate limits, policy simulation, audit tampering detection, credential-scope rejection, and unknown payment outcomes. The PowerShell demo exercises the first approval path; the Go tests exercise the deeper scenarios.
