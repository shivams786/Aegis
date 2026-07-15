package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultServiceName     = "aegis-gateway"
	defaultEnvironment     = "development"
	defaultHTTPAddr        = ":8080"
	defaultShutdownTimeout = 10 * time.Second
)

// Config contains only process-level configuration. Tenant, policy, and tool
// configuration are durable control-plane data and must not be smuggled in here.
type Config struct {
	ServiceName     string
	Environment     string
	HTTPAddr        string
	DatabaseURL     string
	RequireDatabase bool
	ShutdownTimeout time.Duration
	LogLevel        string
	OTELEndpoint    string
	Auth            AuthConfig
	Sidecars        SidecarConfig
	Worker          WorkerConfig
}

type AuthConfig struct {
	Enabled             bool
	Issuer              string
	Audiences           []string
	JWKSURL             string
	JWKSFile            string
	JWKSJSON            string
	RequiredScopes      []string
	ApprovedAlgorithms  []string
	RequiredTokenType   string
	ClockSkew           time.Duration
	ProtectedResourceID string
}

type SidecarConfig struct {
	OPA     OPAConfig
	OpenBao OpenBaoConfig
	Redis   RedisConfig
	NATS    NATSConfig
}

type OPAConfig struct {
	URL           string
	DecisionPath  string
	PolicyHash    string
	PolicyVersion string
	Timeout       time.Duration
}

type OpenBaoConfig struct {
	Address string
	Token   string
	Mount   string
}

type RedisConfig struct {
	Addr   string
	Prefix string
}

type NATSConfig struct {
	Addr    string
	Subject string
}

type WorkerConfig struct {
	OutboxInterval               time.Duration
	OutboxBatchSize              int
	OutboxMaxAttempts            int
	ApprovalExpiryInterval       time.Duration
	BudgetSweepInterval          time.Duration
	BudgetReservationTTL         time.Duration
	BudgetSweepBatchSize         int
	ReconciliationInterval       time.Duration
	ReconciliationBatchSize      int
	ReconciliationLeaseDuration  time.Duration
	ReconciliationRetryAfter     time.Duration
	ReconciliationLeaseOwner     string
	PolicySimulationInterval     time.Duration
	PolicySimulationBatchSize    int
	PolicySimulationLeaseDuration time.Duration
	PolicySimulationRetryAfter   time.Duration
	PolicySimulationLeaseOwner   string
	AuditRootInterval            time.Duration
	AuditRootSigner              string
}

func LoadFromEnv() (Config, error) {
	cfg := Config{
		ServiceName:     getenv("AEGIS_SERVICE_NAME", defaultServiceName),
		Environment:     getenv("AEGIS_ENVIRONMENT", defaultEnvironment),
		HTTPAddr:        getenv("AEGIS_HTTP_ADDR", defaultHTTPAddr),
		DatabaseURL:     os.Getenv("AEGIS_DATABASE_URL"),
		RequireDatabase: getenvBool("AEGIS_REQUIRE_DATABASE", true),
		ShutdownTimeout: getenvDuration("AEGIS_SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
		LogLevel:        getenv("AEGIS_LOG_LEVEL", "info"),
		OTELEndpoint:    os.Getenv("AEGIS_OTEL_EXPORTER_OTLP_ENDPOINT"),
		Auth: AuthConfig{
			Enabled:             getenvBool("AEGIS_AUTH_ENABLED", false),
			Issuer:              os.Getenv("AEGIS_AUTH_ISSUER"),
			Audiences:           getenvList("AEGIS_AUTH_AUDIENCE"),
			JWKSURL:             os.Getenv("AEGIS_AUTH_JWKS_URL"),
			JWKSFile:            os.Getenv("AEGIS_AUTH_JWKS_FILE"),
			JWKSJSON:            os.Getenv("AEGIS_AUTH_JWKS_JSON"),
			RequiredScopes:      getenvList("AEGIS_AUTH_REQUIRED_SCOPES"),
			ApprovedAlgorithms:  getenvListDefault("AEGIS_AUTH_APPROVED_ALGORITHMS", []string{"RS256"}),
			RequiredTokenType:   getenv("AEGIS_AUTH_REQUIRED_TOKEN_TYPE", "Bearer"),
			ClockSkew:           getenvDuration("AEGIS_AUTH_CLOCK_SKEW", 30*time.Second),
			ProtectedResourceID: getenv("AEGIS_AUTH_PROTECTED_RESOURCE_ID", "http://localhost:8080"),
		},
		Sidecars: SidecarConfig{
			OPA: OPAConfig{
				URL:           strings.TrimRight(os.Getenv("AEGIS_OPA_URL"), "/"),
				DecisionPath:  strings.Trim(getenv("AEGIS_OPA_DECISION_PATH", "aegis/authz/decision"), "/"),
				PolicyHash:    os.Getenv("AEGIS_OPA_POLICY_HASH"),
				PolicyVersion: getenv("AEGIS_OPA_POLICY_VERSION", "local-bundle"),
				Timeout:       getenvDuration("AEGIS_OPA_TIMEOUT", 2*time.Second),
			},
			OpenBao: OpenBaoConfig{
				Address: strings.TrimRight(os.Getenv("AEGIS_OPENBAO_ADDR"), "/"),
				Token:   os.Getenv("AEGIS_OPENBAO_TOKEN"),
				Mount:   getenv("AEGIS_OPENBAO_MOUNT", "secret"),
			},
			Redis: RedisConfig{
				Addr:   os.Getenv("AEGIS_REDIS_ADDR"),
				Prefix: getenv("AEGIS_REDIS_PREFIX", "aegis:ratelimit:"),
			},
			NATS: NATSConfig{
				Addr:    os.Getenv("AEGIS_NATS_ADDR"),
				Subject: getenv("AEGIS_NATS_SUBJECT", "aegis.events"),
			},
		},
		Worker: WorkerConfig{
			OutboxInterval:               getenvDuration("AEGIS_WORKER_OUTBOX_INTERVAL", 2*time.Second),
			OutboxBatchSize:              getenvInt("AEGIS_WORKER_OUTBOX_BATCH_SIZE", 50),
			OutboxMaxAttempts:            getenvInt("AEGIS_WORKER_OUTBOX_MAX_ATTEMPTS", 5),
			ApprovalExpiryInterval:       getenvDuration("AEGIS_WORKER_APPROVAL_EXPIRY_INTERVAL", 30*time.Second),
			BudgetSweepInterval:          getenvDuration("AEGIS_WORKER_BUDGET_SWEEP_INTERVAL", 30*time.Second),
			BudgetReservationTTL:         getenvDuration("AEGIS_WORKER_BUDGET_RESERVATION_TTL", 15*time.Minute),
			BudgetSweepBatchSize:         getenvInt("AEGIS_WORKER_BUDGET_SWEEP_BATCH_SIZE", 50),
			ReconciliationInterval:       getenvDuration("AEGIS_WORKER_RECONCILIATION_INTERVAL", 30*time.Second),
			ReconciliationBatchSize:      getenvInt("AEGIS_WORKER_RECONCILIATION_BATCH_SIZE", 25),
			ReconciliationLeaseDuration:  getenvDuration("AEGIS_WORKER_RECONCILIATION_LEASE_DURATION", 2*time.Minute),
			ReconciliationRetryAfter:     getenvDuration("AEGIS_WORKER_RECONCILIATION_RETRY_AFTER", time.Minute),
			ReconciliationLeaseOwner:     getenv("AEGIS_WORKER_RECONCILIATION_LEASE_OWNER", "aegis-worker"),
			PolicySimulationInterval:     getenvDuration("AEGIS_WORKER_POLICY_SIMULATION_INTERVAL", time.Minute),
			PolicySimulationBatchSize:    getenvInt("AEGIS_WORKER_POLICY_SIMULATION_BATCH_SIZE", 10),
			PolicySimulationLeaseDuration: getenvDuration("AEGIS_WORKER_POLICY_SIMULATION_LEASE_DURATION", 5*time.Minute),
			PolicySimulationRetryAfter:   getenvDuration("AEGIS_WORKER_POLICY_SIMULATION_RETRY_AFTER", 5*time.Minute),
			PolicySimulationLeaseOwner:   getenv("AEGIS_WORKER_POLICY_SIMULATION_LEASE_OWNER", "aegis-worker"),
			AuditRootInterval:            getenvDuration("AEGIS_WORKER_AUDIT_ROOT_INTERVAL", time.Minute),
			AuditRootSigner:              getenv("AEGIS_WORKER_AUDIT_ROOT_SIGNER", "aegis-dev-signer"),
		},
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	var errs []error
	if strings.TrimSpace(c.ServiceName) == "" {
		errs = append(errs, errors.New("AEGIS_SERVICE_NAME must not be empty"))
	}
	if strings.TrimSpace(c.Environment) == "" {
		errs = append(errs, errors.New("AEGIS_ENVIRONMENT must not be empty"))
	}
	if strings.TrimSpace(c.HTTPAddr) == "" {
		errs = append(errs, errors.New("AEGIS_HTTP_ADDR must not be empty"))
	}
	if c.ShutdownTimeout <= 0 {
		errs = append(errs, errors.New("AEGIS_SHUTDOWN_TIMEOUT must be positive"))
	}
	if c.RequireDatabase && strings.TrimSpace(c.DatabaseURL) == "" {
		errs = append(errs, errors.New("AEGIS_DATABASE_URL is required when AEGIS_REQUIRE_DATABASE=true"))
	}
	if c.DatabaseURL != "" {
		parsed, err := url.Parse(c.DatabaseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			errs = append(errs, errors.New("AEGIS_DATABASE_URL must be a valid PostgreSQL URL"))
		}
	}
	if c.Sidecars.OPA.URL != "" {
		parsed, err := url.Parse(c.Sidecars.OPA.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			errs = append(errs, errors.New("AEGIS_OPA_URL must be a valid URL"))
		}
		if strings.TrimSpace(c.Sidecars.OPA.DecisionPath) == "" {
			errs = append(errs, errors.New("AEGIS_OPA_DECISION_PATH must not be empty when AEGIS_OPA_URL is set"))
		}
		if c.Sidecars.OPA.Timeout <= 0 {
			errs = append(errs, errors.New("AEGIS_OPA_TIMEOUT must be positive"))
		}
	}
	if c.Sidecars.OpenBao.Address != "" {
		parsed, err := url.Parse(c.Sidecars.OpenBao.Address)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			errs = append(errs, errors.New("AEGIS_OPENBAO_ADDR must be a valid URL"))
		}
	}
	if c.Worker.OutboxInterval < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_OUTBOX_INTERVAL must not be negative"))
	}
	if c.Worker.OutboxBatchSize < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_OUTBOX_BATCH_SIZE must not be negative"))
	}
	if c.Worker.OutboxMaxAttempts < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_OUTBOX_MAX_ATTEMPTS must not be negative"))
	}
	if c.Worker.ApprovalExpiryInterval < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_APPROVAL_EXPIRY_INTERVAL must not be negative"))
	}
	if c.Worker.BudgetSweepInterval < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_BUDGET_SWEEP_INTERVAL must not be negative"))
	}
	if c.Worker.BudgetReservationTTL < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_BUDGET_RESERVATION_TTL must not be negative"))
	}
	if c.Worker.BudgetSweepBatchSize < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_BUDGET_SWEEP_BATCH_SIZE must not be negative"))
	}
	if c.Worker.ReconciliationInterval < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_RECONCILIATION_INTERVAL must not be negative"))
	}
	if c.Worker.ReconciliationBatchSize < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_RECONCILIATION_BATCH_SIZE must not be negative"))
	}
	if c.Worker.ReconciliationLeaseDuration < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_RECONCILIATION_LEASE_DURATION must not be negative"))
	}
	if c.Worker.ReconciliationRetryAfter < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_RECONCILIATION_RETRY_AFTER must not be negative"))
	}
	if strings.TrimSpace(c.Worker.ReconciliationLeaseOwner) == "" {
		errs = append(errs, errors.New("AEGIS_WORKER_RECONCILIATION_LEASE_OWNER must not be empty"))
	}
	if c.Worker.PolicySimulationInterval < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_POLICY_SIMULATION_INTERVAL must not be negative"))
	}
	if c.Worker.PolicySimulationBatchSize < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_POLICY_SIMULATION_BATCH_SIZE must not be negative"))
	}
	if c.Worker.PolicySimulationLeaseDuration < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_POLICY_SIMULATION_LEASE_DURATION must not be negative"))
	}
	if c.Worker.PolicySimulationRetryAfter < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_POLICY_SIMULATION_RETRY_AFTER must not be negative"))
	}
	if strings.TrimSpace(c.Worker.PolicySimulationLeaseOwner) == "" {
		errs = append(errs, errors.New("AEGIS_WORKER_POLICY_SIMULATION_LEASE_OWNER must not be empty"))
	}
	if c.Worker.AuditRootInterval < 0 {
		errs = append(errs, errors.New("AEGIS_WORKER_AUDIT_ROOT_INTERVAL must not be negative"))
	}
	if strings.TrimSpace(c.Worker.AuditRootSigner) == "" {
		errs = append(errs, errors.New("AEGIS_WORKER_AUDIT_ROOT_SIGNER must not be empty"))
	}
	if c.Auth.Enabled {
		if strings.TrimSpace(c.Auth.Issuer) == "" {
			errs = append(errs, errors.New("AEGIS_AUTH_ISSUER is required when AEGIS_AUTH_ENABLED=true"))
		}
		if len(c.Auth.Audiences) == 0 {
			errs = append(errs, errors.New("AEGIS_AUTH_AUDIENCE is required when AEGIS_AUTH_ENABLED=true"))
		}
		jwksSources := 0
		for _, value := range []string{c.Auth.JWKSURL, c.Auth.JWKSFile, c.Auth.JWKSJSON} {
			if strings.TrimSpace(value) != "" {
				jwksSources++
			}
		}
		if jwksSources != 1 {
			errs = append(errs, errors.New("exactly one JWKS source is required when AEGIS_AUTH_ENABLED=true"))
		}
		if c.Auth.JWKSURL != "" {
			parsed, err := url.Parse(c.Auth.JWKSURL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				errs = append(errs, errors.New("AEGIS_AUTH_JWKS_URL must be a valid URL"))
			}
		}
		if len(c.Auth.ApprovedAlgorithms) == 0 {
			errs = append(errs, errors.New("at least one approved JWT algorithm is required"))
		}
		if c.Auth.ClockSkew < 0 {
			errs = append(errs, errors.New("AEGIS_AUTH_CLOCK_SKEW must not be negative"))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c Config) RedactedDatabaseURL() string {
	if c.DatabaseURL == "" {
		return ""
	}
	parsed, err := url.Parse(c.DatabaseURL)
	if err != nil {
		return "<invalid>"
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		parsed.User = url.UserPassword(username, "redacted")
	}
	return parsed.String()
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func getenvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func getenvList(key string) []string {
	return splitList(os.Getenv(key))
}

func getenvListDefault(key string, fallback []string) []string {
	values := splitList(os.Getenv(key))
	if len(values) == 0 {
		return fallback
	}
	return values
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func (c Config) String() string {
	return fmt.Sprintf("service=%s env=%s addr=%s db=%s require_db=%t otel=%t auth=%t",
		c.ServiceName,
		c.Environment,
		c.HTTPAddr,
		c.RedactedDatabaseURL(),
		c.RequireDatabase,
		c.OTELEndpoint != "",
		c.Auth.Enabled,
	) + fmt.Sprintf(" opa=%t redis=%t nats=%t openbao=%t",
		c.Sidecars.OPA.URL != "",
		c.Sidecars.Redis.Addr != "",
		c.Sidecars.NATS.Addr != "",
		c.Sidecars.OpenBao.Address != "",
	)
}
