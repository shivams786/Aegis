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
	)
}
