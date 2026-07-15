package config

import (
	"testing"
	"time"
)

func TestValidateRequiresDatabaseURLWhenStrict(t *testing.T) {
	cfg := Config{
		ServiceName:     "aegis-gateway",
		Environment:     "test",
		HTTPAddr:        ":0",
		RequireDatabase: true,
		ShutdownTimeout: defaultShutdownTimeout,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected strict configuration to require a database URL")
	}
}

func TestRedactedDatabaseURLDoesNotLeakPassword(t *testing.T) {
	cfg := Config{DatabaseURL: "postgres://aegis:secret@localhost:5432/aegis?sslmode=disable"}

	got := cfg.RedactedDatabaseURL()
	if got == cfg.DatabaseURL {
		t.Fatal("database URL was not redacted")
	}
	if contains(got, "secret") {
		t.Fatalf("database URL leaked password: %s", got)
	}
}

func TestValidateAuthRequiresExactlyOneJWKSSource(t *testing.T) {
	cfg := Config{
		ServiceName:     "aegis-gateway",
		Environment:     "test",
		HTTPAddr:        ":0",
		DatabaseURL:     "postgres://aegis:aegis_dev_password@localhost:5432/aegis?sslmode=disable",
		RequireDatabase: true,
		ShutdownTimeout: defaultShutdownTimeout,
		Auth: AuthConfig{
			Enabled:            true,
			Issuer:             "http://localhost:8081/realms/aegis",
			Audiences:          []string{"aegis-gateway"},
			ApprovedAlgorithms: []string{"RS256"},
			RequiredTokenType:  "Bearer",
			JWKSJSON:           `{"keys":[]}`,
			JWKSURL:            "http://localhost:8081/realms/aegis/protocol/openid-connect/certs",
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected multiple JWKS sources to fail validation")
	}
}

func TestLoadFromEnvParsesSidecarConfiguration(t *testing.T) {
	t.Setenv("AEGIS_REQUIRE_DATABASE", "false")
	t.Setenv("AEGIS_AUTH_ENABLED", "false")
	t.Setenv("AEGIS_OPA_URL", "http://localhost:8181/")
	t.Setenv("AEGIS_OPA_DECISION_PATH", "/aegis/authz/decision/")
	t.Setenv("AEGIS_OPA_TIMEOUT", "750ms")
	t.Setenv("AEGIS_OPENBAO_ADDR", "http://localhost:8200/")
	t.Setenv("AEGIS_OPENBAO_TOKEN", "dev-token")
	t.Setenv("AEGIS_REDIS_ADDR", "localhost:6379")
	t.Setenv("AEGIS_NATS_ADDR", "localhost:4222")
	t.Setenv("AEGIS_NATS_SUBJECT", "aegis.audit")
	t.Setenv("AEGIS_WORKER_OUTBOX_INTERVAL", "500ms")
	t.Setenv("AEGIS_WORKER_OUTBOX_BATCH_SIZE", "25")
	t.Setenv("AEGIS_WORKER_OUTBOX_MAX_ATTEMPTS", "3")
	t.Setenv("AEGIS_WORKER_APPROVAL_EXPIRY_INTERVAL", "2s")
	t.Setenv("AEGIS_WORKER_BUDGET_SWEEP_INTERVAL", "3s")
	t.Setenv("AEGIS_WORKER_BUDGET_RESERVATION_TTL", "10m")
	t.Setenv("AEGIS_WORKER_BUDGET_SWEEP_BATCH_SIZE", "17")
	t.Setenv("AEGIS_WORKER_RECONCILIATION_INTERVAL", "4s")
	t.Setenv("AEGIS_WORKER_RECONCILIATION_BATCH_SIZE", "9")
	t.Setenv("AEGIS_WORKER_RECONCILIATION_LEASE_DURATION", "45s")
	t.Setenv("AEGIS_WORKER_RECONCILIATION_RETRY_AFTER", "90s")
	t.Setenv("AEGIS_WORKER_RECONCILIATION_LEASE_OWNER", "worker-a")
	t.Setenv("AEGIS_WORKER_POLICY_SIMULATION_INTERVAL", "6s")
	t.Setenv("AEGIS_WORKER_POLICY_SIMULATION_BATCH_SIZE", "4")
	t.Setenv("AEGIS_WORKER_POLICY_SIMULATION_LEASE_DURATION", "7m")
	t.Setenv("AEGIS_WORKER_POLICY_SIMULATION_RETRY_AFTER", "8m")
	t.Setenv("AEGIS_WORKER_POLICY_SIMULATION_LEASE_OWNER", "policy-worker")
	t.Setenv("AEGIS_WORKER_AUDIT_ROOT_INTERVAL", "5s")
	t.Setenv("AEGIS_WORKER_AUDIT_ROOT_SIGNER", "test-signer")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Sidecars.OPA.URL != "http://localhost:8181" || cfg.Sidecars.OPA.DecisionPath != "aegis/authz/decision" {
		t.Fatalf("unexpected opa config: %#v", cfg.Sidecars.OPA)
	}
	if cfg.Sidecars.OPA.Timeout != 750*time.Millisecond {
		t.Fatalf("unexpected opa timeout: %s", cfg.Sidecars.OPA.Timeout)
	}
	if cfg.Sidecars.OpenBao.Address != "http://localhost:8200" || cfg.Sidecars.OpenBao.Token != "dev-token" {
		t.Fatalf("unexpected openbao config: %#v", cfg.Sidecars.OpenBao)
	}
	if cfg.Sidecars.Redis.Addr != "localhost:6379" || cfg.Sidecars.NATS.Subject != "aegis.audit" {
		t.Fatalf("unexpected sidecar config: %#v", cfg.Sidecars)
	}
	if cfg.Worker.OutboxInterval != 500*time.Millisecond ||
		cfg.Worker.OutboxBatchSize != 25 ||
		cfg.Worker.OutboxMaxAttempts != 3 ||
		cfg.Worker.ApprovalExpiryInterval != 2*time.Second ||
		cfg.Worker.BudgetSweepInterval != 3*time.Second ||
		cfg.Worker.BudgetReservationTTL != 10*time.Minute ||
		cfg.Worker.BudgetSweepBatchSize != 17 ||
		cfg.Worker.ReconciliationInterval != 4*time.Second ||
		cfg.Worker.ReconciliationBatchSize != 9 ||
		cfg.Worker.ReconciliationLeaseDuration != 45*time.Second ||
		cfg.Worker.ReconciliationRetryAfter != 90*time.Second ||
		cfg.Worker.ReconciliationLeaseOwner != "worker-a" ||
		cfg.Worker.PolicySimulationInterval != 6*time.Second ||
		cfg.Worker.PolicySimulationBatchSize != 4 ||
		cfg.Worker.PolicySimulationLeaseDuration != 7*time.Minute ||
		cfg.Worker.PolicySimulationRetryAfter != 8*time.Minute ||
		cfg.Worker.PolicySimulationLeaseOwner != "policy-worker" ||
		cfg.Worker.AuditRootInterval != 5*time.Second ||
		cfg.Worker.AuditRootSigner != "test-signer" {
		t.Fatalf("unexpected worker config: %#v", cfg.Worker)
	}
}

func TestValidateRejectsInvalidOPAURL(t *testing.T) {
	cfg := Config{
		ServiceName:     "aegis-gateway",
		Environment:     "test",
		HTTPAddr:        ":0",
		RequireDatabase: false,
		ShutdownTimeout: defaultShutdownTimeout,
		Sidecars: SidecarConfig{
			OPA: OPAConfig{URL: "://bad", DecisionPath: "aegis/authz/decision", Timeout: time.Second},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid opa url to fail validation")
	}
}

func contains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
