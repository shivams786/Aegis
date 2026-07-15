package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/config"
	"github.com/aegis/aegis/internal/core"
	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/outbox"
	"github.com/aegis/aegis/internal/storage"
	"github.com/aegis/aegis/internal/tenancy"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel"
)

type Server struct {
	cfg    config.Config
	store  *storage.Store
	logger *slog.Logger
	auth   *authn.Validator
	engine *core.Engine
}

func NewRouter(cfg config.Config, store *storage.Store, logger *slog.Logger, validator *authn.Validator, engine *core.Engine) http.Handler {
	server := &Server{cfg: cfg, store: store, logger: logger, auth: validator, engine: engine}
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(30 * time.Second))
	router.Use(server.accessLog)

	router.Get("/live", server.live)
	router.Get("/ready", server.ready)
	router.Get("/metrics", server.metrics)
	router.Get("/.well-known/oauth-protected-resource", server.protectedResourceMetadata)

	protected := router.With(server.authenticate)
	protected.Post("/mcp", server.mcp)
	protected.Route("/v1", func(r chi.Router) {
		r.Get("/", server.version)
		r.Get("/whoami", server.whoami)
		r.Post("/invocations", server.submitInvocation)
		r.Get("/invocations/{invocation_id}", server.getInvocation)
		r.Post("/invocations/{invocation_id}/reconcile", server.reconcileInvocation)
		r.Get("/approvals", server.listApprovals)
		r.Post("/approvals/{approval_request_id}/approve", server.approve)
		r.Post("/approvals/{approval_request_id}/reject", server.reject)
		r.Get("/policy/bundles", server.listPolicyBundles)
		r.Post("/policy/bundles", server.createPolicyBundle)
		r.Get("/policy/bundles/{bundle_id}", server.getPolicyBundle)
		r.Post("/policy/bundles/{bundle_id}/activate", server.activatePolicyBundle)
		r.Get("/policy/simulations", server.listPolicySimulations)
		r.Post("/policy/simulations", server.createPolicySimulation)
		r.Get("/policy/simulations/{simulation_id}", server.getPolicySimulation)
		r.Get("/tools", server.listTools)
		r.Get("/audit/events", server.auditEvents)
		r.Post("/audit/verify", server.verifyAudit)
		r.Get("/audit/roots", server.auditRoot)
	})

	return router
}

func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": s.cfg.ServiceName,
		"time":    time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("github.com/aegis/aegis/internal/api").Start(r.Context(), "aegis.ready")
	defer span.End()

	if err := s.store.Ping(ctx); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "required dependency is unavailable", "POSTGRES_UNAVAILABLE")
		return
	}
	dependencies := map[string]string{"postgres": "ok"}
	if s.cfg.Sidecars.OPA.URL != "" {
		if err := s.checkOPA(ctx); err != nil {
			s.logger.Warn("opa readiness check failed", "error", err)
			writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "required dependency is unavailable", "OPA_UNAVAILABLE")
			return
		}
		dependencies["opa"] = "ok"
	}
	if s.cfg.Sidecars.Redis.Addr != "" {
		if err := s.checkTCPDependency(ctx, s.cfg.Sidecars.Redis.Addr); err != nil {
			s.logger.Warn("redis readiness check failed", "error", err)
			writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "required dependency is unavailable", "REDIS_UNAVAILABLE")
			return
		}
		dependencies["redis"] = "ok"
	}
	if s.cfg.Sidecars.OpenBao.Address != "" && s.cfg.Sidecars.OpenBao.Token != "" {
		if err := s.checkOpenBao(ctx); err != nil {
			s.logger.Warn("openbao readiness check failed", "error", err)
			writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "required dependency is unavailable", "OPENBAO_UNAVAILABLE")
			return
		}
		dependencies["openbao"] = "ok"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ready",
		"dependencies": dependencies,
	})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	ready := 1
	if err := s.store.Ping(r.Context()); err != nil {
		ready = 0
	}
	if ready == 1 && s.cfg.Sidecars.OPA.URL != "" {
		if err := s.checkOPA(r.Context()); err != nil {
			ready = 0
		}
	}
	if ready == 1 && s.cfg.Sidecars.Redis.Addr != "" {
		if err := s.checkTCPDependency(r.Context(), s.cfg.Sidecars.Redis.Addr); err != nil {
			ready = 0
		}
	}
	if ready == 1 && s.cfg.Sidecars.OpenBao.Address != "" && s.cfg.Sidecars.OpenBao.Token != "" {
		if err := s.checkOpenBao(r.Context()); err != nil {
			ready = 0
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "# HELP aegis_ready Whether the gateway can safely process durable requests.\n")
	_, _ = fmt.Fprintf(w, "# TYPE aegis_ready gauge\n")
	_, _ = fmt.Fprintf(w, "aegis_ready{service=%q} %d\n", s.cfg.ServiceName, ready)
	_, _ = fmt.Fprintf(w, "# HELP aegis_build_info Static service build information.\n")
	_, _ = fmt.Fprintf(w, "# TYPE aegis_build_info gauge\n")
	_, _ = fmt.Fprintf(w, "aegis_build_info{service=%q,environment=%q} 1\n", s.cfg.ServiceName, s.cfg.Environment)
}

func (s *Server) checkOPA(ctx context.Context) error {
	timeout := s.cfg.Sidecars.OPA.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Sidecars.OPA.URL+"/health", nil)
	if err != nil {
		return err
	}
	client := http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("opa health returned non-2xx status")
	}
	return nil
}

func (s *Server) checkOpenBao(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Sidecars.OpenBao.Address+"/v1/sys/health", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", s.cfg.Sidecars.OpenBao.Token)
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("openbao health returned non-2xx status")
	}
	return nil
}

func (s *Server) checkTCPDependency(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": s.cfg.ServiceName,
		"version": "v1",
	})
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	identity, err := authn.IdentityFromContext(r.Context())
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "valid authentication is required", "AUTHENTICATION_REQUIRED")
		return
	}
	writeJSON(w, http.StatusOK, identity)
}

func (s *Server) submitInvocation(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "invocation engine is not configured", "INVOCATION_ENGINE_NOT_CONFIGURED")
		return
	}
	var req invocation.Request
	if err := decodeJSON(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "bad_request", "request body is invalid", "INVALID_JSON")
		return
	}
	s.bindIdentity(r, &req)
	resp, err := s.engine.Submit(r.Context(), req)
	if err != nil {
		s.logger.Error("invocation failed", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "invocation failed safely", "INVOCATION_FAILED")
		return
	}
	status := http.StatusAccepted
	if resp.State == invocation.StateSucceeded {
		status = http.StatusOK
	}
	if resp.State == invocation.StateDenied {
		status = http.StatusForbidden
	}
	s.enqueueInvocationOutbox(r, req.TenantID, "InvocationStateChanged", resp)
	writeJSON(w, status, resp)
}

func (s *Server) getInvocation(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "invocation engine is not configured", "INVOCATION_ENGINE_NOT_CONFIGURED")
		return
	}
	tenantID := tenantFromRequest(r)
	resp, ok := s.engine.GetInvocation(tenantID, chi.URLParam(r, "invocation_id"))
	if !ok {
		writeProblem(w, http.StatusNotFound, "not_found", "resource was not found", "NOT_FOUND")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) reconcileInvocation(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "invocation engine is not configured", "INVOCATION_ENGINE_NOT_CONFIGURED")
		return
	}
	tenantID := tenantFromRequest(r)
	resp, err := s.engine.Reconcile(r.Context(), tenantID, chi.URLParam(r, "invocation_id"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "resource was not found", "NOT_FOUND")
		return
	}
	s.enqueueInvocationOutbox(r, tenantID, "InvocationReconciled", resp)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) listTools(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "invocation engine is not configured", "INVOCATION_ENGINE_NOT_CONFIGURED")
		return
	}
	identity, _ := authn.IdentityFromContext(r.Context())
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		tenantID = identity.TenantID
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": s.engine.ListTools(tenantID, scopesForRequest(r))})
}

func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "invocation engine is not configured", "INVOCATION_ENGINE_NOT_CONFIGURED")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": s.engine.PendingApprovals(tenantFromRequest(r))})
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	s.decideApproval(w, r, true)
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	s.decideApproval(w, r, false)
}

func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	if s.engine == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "invocation engine is not configured", "INVOCATION_ENGINE_NOT_CONFIGURED")
		return
	}
	var body struct {
		Approver authn.Subject `json:"approver"`
		Reason   string        `json:"reason"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, http.StatusBadRequest, "bad_request", "request body is invalid", "INVALID_JSON")
		return
	}
	if identity, err := authn.IdentityFromContext(r.Context()); err == nil && body.Approver.ID == "" {
		body.Approver = identity.Subject
	}
	tenantID := tenantFromRequest(r)
	approvalID := chi.URLParam(r, "approval_request_id")
	var (
		resp invocation.Response
		err  error
	)
	if approve {
		resp, err = s.engine.Approve(r.Context(), tenantID, approvalID, body.Approver, body.Reason)
	} else {
		resp, err = s.engine.Reject(tenantID, approvalID, body.Approver, body.Reason)
	}
	if err != nil {
		writeProblem(w, http.StatusForbidden, "forbidden", "approval decision was rejected", "APPROVAL_DECISION_REJECTED")
		return
	}
	s.enqueueInvocationOutbox(r, tenantID, "ApprovalDecisionApplied", resp)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) createPolicyBundle(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.store.Pool() == nil {
		writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "policy bundle storage is unavailable", "POSTGRES_UNAVAILABLE")
		return
	}
	var body storage.PolicyBundleCreate
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, http.StatusBadRequest, "bad_request", "request body is invalid", "INVALID_JSON")
		return
	}
	body.TenantID = tenantFromRequest(r)
	if identity, err := authn.IdentityFromContext(r.Context()); err == nil {
		body.CreatedBySubjectID = identity.Subject.ID
	}
	body.TraceContext = map[string]any{"request_id": middleware.GetReqID(r.Context())}
	bundle, err := s.store.CreatePolicyBundle(r.Context(), body)
	if err != nil {
		s.logger.Warn("create policy bundle failed", "error", err)
		writeProblem(w, http.StatusBadRequest, "bad_request", "policy bundle request is invalid", "POLICY_BUNDLE_INVALID")
		return
	}
	writeJSON(w, http.StatusCreated, bundle)
}

func (s *Server) listPolicyBundles(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.store.Pool() == nil {
		writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "policy bundle storage is unavailable", "POSTGRES_UNAVAILABLE")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 100 {
			writeProblem(w, http.StatusBadRequest, "bad_request", "limit must be between 1 and 100", "INVALID_LIMIT")
			return
		}
		limit = parsed
	}
	bundles, err := s.store.ListPolicyBundles(r.Context(), tenantFromRequest(r), limit)
	if err != nil {
		s.logger.Warn("list policy bundles failed", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "policy bundles could not be loaded", "POLICY_BUNDLE_LIST_FAILED")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bundles": bundles})
}

func (s *Server) getPolicyBundle(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.store.Pool() == nil {
		writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "policy bundle storage is unavailable", "POSTGRES_UNAVAILABLE")
		return
	}
	bundle, err := s.store.GetPolicyBundle(r.Context(), tenantFromRequest(r), chi.URLParam(r, "bundle_id"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "resource was not found", "NOT_FOUND")
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) activatePolicyBundle(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.store.Pool() == nil {
		writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "policy bundle storage is unavailable", "POSTGRES_UNAVAILABLE")
		return
	}
	traceContext := map[string]any{"request_id": middleware.GetReqID(r.Context())}
	bundle, err := s.store.ActivatePolicyBundle(r.Context(), tenantFromRequest(r), chi.URLParam(r, "bundle_id"), traceContext)
	if err != nil {
		s.logger.Warn("activate policy bundle failed", "error", err)
		writeProblem(w, http.StatusBadRequest, "bad_request", "policy bundle could not be activated", "POLICY_BUNDLE_ACTIVATION_FAILED")
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) createPolicySimulation(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.store.Pool() == nil {
		writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "policy simulation storage is unavailable", "POSTGRES_UNAVAILABLE")
		return
	}
	var body storage.PolicySimulationRunCreate
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, http.StatusBadRequest, "bad_request", "request body is invalid", "INVALID_JSON")
		return
	}
	body.TenantID = tenantFromRequest(r)
	if identity, err := authn.IdentityFromContext(r.Context()); err == nil {
		body.RequestedBySubjectID = identity.Subject.ID
	}
	body.TraceContext = map[string]any{"request_id": middleware.GetReqID(r.Context())}
	run, err := s.store.CreatePolicySimulationRun(r.Context(), body)
	if err != nil {
		s.logger.Warn("create policy simulation failed", "error", err)
		writeProblem(w, http.StatusBadRequest, "bad_request", "policy simulation request is invalid", "POLICY_SIMULATION_INVALID")
		return
	}
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) listPolicySimulations(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.store.Pool() == nil {
		writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "policy simulation storage is unavailable", "POSTGRES_UNAVAILABLE")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 100 {
			writeProblem(w, http.StatusBadRequest, "bad_request", "limit must be between 1 and 100", "INVALID_LIMIT")
			return
		}
		limit = parsed
	}
	runs, err := s.store.ListPolicySimulationRuns(r.Context(), tenantFromRequest(r), limit)
	if err != nil {
		s.logger.Warn("list policy simulations failed", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "policy simulations could not be loaded", "POLICY_SIMULATION_LIST_FAILED")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"simulations": runs})
}

func (s *Server) getPolicySimulation(w http.ResponseWriter, r *http.Request) {
	if s.store == nil || s.store.Pool() == nil {
		writeProblem(w, http.StatusServiceUnavailable, "dependency_unavailable", "policy simulation storage is unavailable", "POSTGRES_UNAVAILABLE")
		return
	}
	run, err := s.store.GetPolicySimulationRun(r.Context(), tenantFromRequest(r), chi.URLParam(r, "simulation_id"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "resource was not found", "NOT_FOUND")
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "invocation engine is not configured", "INVOCATION_ENGINE_NOT_CONFIGURED")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": s.engine.AuditEvents(tenantFromRequest(r))})
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "invocation engine is not configured", "INVOCATION_ENGINE_NOT_CONFIGURED")
		return
	}
	if err := s.engine.VerifyAudit(tenantFromRequest(r)); err != nil {
		writeProblem(w, http.StatusConflict, "audit_verification_failed", "audit chain verification failed", "AUDIT_CHAIN_BROKEN")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "verified"})
}

func (s *Server) auditRoot(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "invocation engine is not configured", "INVOCATION_ENGINE_NOT_CONFIGURED")
		return
	}
	root, err := s.engine.AuditRoot(tenantFromRequest(r))
	if err != nil {
		writeProblem(w, http.StatusConflict, "audit_root_unavailable", "audit root is not available", "AUDIT_ROOT_UNAVAILABLE")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roots": []any{root}})
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "invocation engine is not configured", "INVOCATION_ENGINE_NOT_CONFIGURED")
		return
	}
	var message struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      any            `json:"id"`
		Method  string         `json:"method"`
		Params  map[string]any `json:"params"`
	}
	if err := decodeJSON(w, r, &message); err != nil {
		writeJSON(w, http.StatusOK, mcpError(nil, -32700, "parse error"))
		return
	}
	switch message.Method {
	case "tools/list":
		tenantID := tenantFromRequest(r)
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": map[string]any{"tools": s.engine.ListTools(tenantID, scopesForRequest(r))}})
	case "tools/call":
		req := mcpInvocationRequest(message, r)
		s.bindIdentity(r, &req)
		resp, err := s.engine.Submit(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusOK, mcpError(message.ID, -32603, "internal error"))
			return
		}
		s.enqueueInvocationOutbox(r, req.TenantID, "MCPInvocationStateChanged", resp)
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": resp})
	default:
		writeJSON(w, http.StatusOK, mcpError(message.ID, -32601, "method not found"))
	}
}

func (s *Server) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := s.cfg.Auth.Issuer
	if issuer == "" {
		issuer = "http://localhost:8081/realms/aegis"
	}
	resource := s.cfg.Auth.ProtectedResourceID
	if resource == "" {
		resource = "http://localhost:8080"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                    resource,
		"authorization_servers":       []string{issuer},
		"bearer_methods_supported":    []string{"header"},
		"scopes_supported":            s.cfg.Auth.RequiredScopes,
		"resource_documentation":      "https://aegis.local/docs/mcp-auth",
		"resource_signing_alg_values": s.cfg.Auth.ApprovedAlgorithms,
	})
}

func (s *Server) notImplemented(reasonCode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, http.StatusNotImplemented, "not_implemented", "endpoint is reserved for the next milestone", reasonCode)
	}
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		if s.auth == nil {
			writeAuthChallenge(w, s.cfg.Auth, "AUTHENTICATION_NOT_CONFIGURED")
			return
		}
		identity, err := s.auth.AuthenticateBearer(r.Header.Get("Authorization"))
		if err != nil {
			s.logger.Info("authentication denied", "reason_code", "JWT_INVALID", "error", err)
			writeAuthChallenge(w, s.cfg.Auth, "JWT_INVALID")
			return
		}
		if s.store != nil && s.store.Pool() != nil {
			resolved, err := s.store.ResolveActingIdentity(r.Context(), identity)
			if err != nil {
				s.logger.Info("authentication denied", "reason_code", "IDENTITY_RESOLUTION_FAILED", "error", err)
				writeAuthChallenge(w, s.cfg.Auth, "IDENTITY_RESOLUTION_FAILED")
				return
			}
			identity = resolved
		}
		ctx := authn.ContextWithIdentity(r.Context(), identity)
		ctx = tenancy.ContextWithTenant(ctx, identity.TenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(recorder, r)
		s.logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.Status(),
			"bytes", recorder.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}

func (s *Server) enqueueInvocationOutbox(r *http.Request, tenantID, eventType string, resp invocation.Response) {
	if s.store == nil || s.store.Pool() == nil || resp.ID == "" {
		return
	}
	if tenantID == "" {
		tenantID = tenantFromRequest(r)
	}
	eventID := fmt.Sprintf("evt_%s_%s_%d", resp.ID, eventType, resp.UpdatedAt.UnixNano())
	event := outbox.Event{
		EventID:          eventID,
		TenantID:         tenantID,
		AggregateID:      resp.ID,
		AggregateVersion: resp.UpdatedAt.UnixNano(),
		EventType:        eventType,
		SchemaVersion:    1,
		OccurredAt:       resp.UpdatedAt,
		Payload: map[string]any{
			"invocation_id":       resp.ID,
			"state":               resp.State,
			"decision":            resp.Decision,
			"reason_codes":        resp.ReasonCodes,
			"approval_request_id": resp.ApprovalRequestID,
		},
		TraceContext: map[string]any{
			"request_id": middleware.GetReqID(r.Context()),
		},
	}
	if _, err := s.store.EnqueueOutboxEvent(r.Context(), event); err != nil {
		s.logger.Warn("enqueue outbox event failed", "event_type", eventType, "invocation_id", resp.ID, "error", err)
	}
}

type problemDetails struct {
	Type       string `json:"type"`
	Title      string `json:"title"`
	Status     int    `json:"status"`
	Detail     string `json:"detail"`
	ReasonCode string `json:"reason_code"`
}

func writeProblem(w http.ResponseWriter, status int, title, detail, reasonCode string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemDetails{
		Type:       "https://aegis.local/problems/" + title,
		Title:      title,
		Status:     status,
		Detail:     detail,
		ReasonCode: reasonCode,
	})
}

func writeAuthChallenge(w http.ResponseWriter, cfg config.AuthConfig, reasonCode string) {
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = "http://localhost:8081/realms/aegis"
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="aegis", authorization_uri="`+issuer+`", error="invalid_token"`)
	writeProblem(w, http.StatusUnauthorized, "unauthorized", "valid authentication is required", reasonCode)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func (s *Server) bindIdentity(r *http.Request, req *invocation.Request) {
	identity, err := authn.IdentityFromContext(r.Context())
	if err != nil {
		return
	}
	req.TenantID = identity.TenantID
	req.Subject = identity.Subject
	req.Agent = identity.Agent
	req.DelegationID = identity.Delegation.ID
	if req.Purpose == "" {
		req.Purpose = identity.Delegation.Purpose
	}
}

func tenantFromRequest(r *http.Request) string {
	if tenantID, err := tenancy.TenantID(r.Context()); err == nil {
		return tenantID
	}
	if tenantID := r.URL.Query().Get("tenant_id"); tenantID != "" {
		return tenantID
	}
	return "tenant_acme"
}

func scopesForRequest(r *http.Request) []string {
	if identity, err := authn.IdentityFromContext(r.Context()); err == nil {
		return identity.Scopes
	}
	return []string{"aegis.invoke", "payments:refund", "payments:read", "crm:read", "crm:export", "messaging:send"}
}

func mcpInvocationRequest(message struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
}, r *http.Request) invocation.Request {
	name, _ := message.Params["name"].(string)
	args, _ := message.Params["arguments"].(map[string]any)
	resource := invocation.Resource{Type: "tenant", ID: tenantFromRequest(r), OwnerTenantID: tenantFromRequest(r)}
	if customerID, _ := args["customer_id"].(string); customerID != "" {
		resource = invocation.Resource{Type: "customer", ID: customerID, OwnerTenantID: tenantFromRequest(r)}
	}
	return invocation.Request{
		TenantID: tenantFromRequest(r), Protocol: invocation.ProtocolMCP, ProtocolRequestID: fmt.Sprint(message.ID),
		IdempotencyKey: fmt.Sprint(message.Params["idempotency_key"]), Tool: invocation.ToolRef{ID: name},
		Action: actionFromTool(name), Resource: resource, Purpose: "customer_support", Arguments: args,
	}
}

func actionFromTool(toolID string) string {
	switch toolID {
	case "payments.refund":
		return "refund"
	case "payments.get_refund":
		return "get_refund"
	case "messaging.send_email":
		return "send_email"
	case "crm.get_customer":
		return "get_customer"
	case "crm.export_customers":
		return "export_customers"
	default:
		return toolID
	}
}

func mcpError(id any, code int, message string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}}
}
