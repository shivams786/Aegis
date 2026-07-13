package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegis/aegis/internal/config"
	"github.com/aegis/aegis/internal/observability"
	"github.com/aegis/aegis/internal/storage"
)

func TestLiveEndpointDoesNotRequireDependencies(t *testing.T) {
	cfg := config.Config{
		ServiceName:     "aegis-gateway",
		Environment:     "test",
		HTTPAddr:        ":0",
		RequireDatabase: false,
		ShutdownTimeout: time.Second,
	}
	router := NewRouter(cfg, &storage.Store{}, observability.NewLogger("test", "error"), nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected /live to return 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestReadyFailsClosedWithoutPostgres(t *testing.T) {
	cfg := config.Config{
		ServiceName:     "aegis-gateway",
		Environment:     "test",
		HTTPAddr:        ":0",
		RequireDatabase: true,
		ShutdownTimeout: time.Second,
	}
	router := NewRouter(cfg, &storage.Store{}, observability.NewLogger("test", "error"), nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected /ready to fail closed, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestProtectedRouteChallengesWhenAuthIsEnabled(t *testing.T) {
	cfg := config.Config{
		ServiceName:     "aegis-gateway",
		Environment:     "test",
		HTTPAddr:        ":0",
		RequireDatabase: false,
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled:             true,
			Issuer:              "http://localhost:8081/realms/aegis",
			Audiences:           []string{"aegis-gateway"},
			ApprovedAlgorithms:  []string{"RS256"},
			RequiredTokenType:   "Bearer",
			ProtectedResourceID: "http://localhost:8080",
		},
	}
	router := NewRouter(cfg, &storage.Store{}, observability.NewLogger("test", "error"), nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected /v1/whoami to require auth, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate challenge")
	}
}
