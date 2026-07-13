//go:build integration

package integration_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aegis/aegis/internal/api"
	"github.com/aegis/aegis/internal/config"
	"github.com/aegis/aegis/internal/observability"
	"github.com/aegis/aegis/internal/storage"
)

func TestGatewayReadinessUsesPostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set AEGIS_TEST_DATABASE_URL to run PostgreSQL integration readiness test")
	}

	cfg := config.Config{
		ServiceName:     "aegis-gateway",
		Environment:     "integration",
		HTTPAddr:        ":0",
		DatabaseURL:     databaseURL,
		RequireDatabase: true,
		ShutdownTimeout: time.Second,
	}

	logger := observability.NewLogger("test", "error")
	store, err := storage.Open(t.Context(), cfg, logger)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := api.NewRouter(cfg, store, logger, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected /ready to return 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
