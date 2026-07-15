package api

import (
	"context"
	"net"
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

func TestOPAReadinessCheckRequiresHealthySidecar(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer opa.Close()
	server := Server{
		cfg: config.Config{
			ServiceName: "aegis-gateway",
			Sidecars: config.SidecarConfig{
				OPA: config.OPAConfig{URL: opa.URL, Timeout: time.Second},
			},
		},
	}

	if err := server.checkOPA(context.Background()); err == nil {
		t.Fatal("expected unhealthy opa sidecar to fail readiness")
	}
}

func TestOPAReadinessCheckAcceptsHealthySidecar(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer opa.Close()
	server := Server{
		cfg: config.Config{
			ServiceName: "aegis-gateway",
			Sidecars: config.SidecarConfig{
				OPA: config.OPAConfig{URL: opa.URL, Timeout: time.Second},
			},
		},
	}

	if err := server.checkOPA(context.Background()); err != nil {
		t.Fatalf("expected healthy opa sidecar: %v", err)
	}
}

func TestOpenBaoReadinessCheckRequiresHealthySidecar(t *testing.T) {
	openbao := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "sealed", http.StatusServiceUnavailable)
	}))
	defer openbao.Close()
	server := Server{
		cfg: config.Config{
			ServiceName: "aegis-gateway",
			Sidecars: config.SidecarConfig{
				OpenBao: config.OpenBaoConfig{Address: openbao.URL, Token: "dev-token"},
			},
		},
	}

	if err := server.checkOpenBao(context.Background()); err == nil {
		t.Fatal("expected unhealthy openbao sidecar to fail readiness")
	}
}

func TestTCPDependencyCheckAcceptsListeningSidecar(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()
	server := Server{}

	if err := server.checkTCPDependency(context.Background(), listener.Addr().String()); err != nil {
		t.Fatalf("expected listening sidecar: %v", err)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("expected readiness probe to connect to listener")
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
