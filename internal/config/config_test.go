package config

import "testing"

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

func contains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
