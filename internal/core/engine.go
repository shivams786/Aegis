package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aegis/aegis/internal/approval"
	"github.com/aegis/aegis/internal/audit"
	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/budget"
	"github.com/aegis/aegis/internal/credentials"
	"github.com/aegis/aegis/internal/delegation"
	"github.com/aegis/aegis/internal/execution"
	"github.com/aegis/aegis/internal/idempotency"
	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/policy"
	"github.com/aegis/aegis/internal/ratelimit"
	"github.com/aegis/aegis/internal/risk"
	"github.com/aegis/aegis/internal/tools"
)

type Engine struct {
	mu          sync.Mutex
	registry    *tools.Registry
	policy      policy.Evaluator
	budgets     *budget.Ledger
	limits      *ratelimit.Limiter
	approvals   *approval.Store
	credentials *credentials.MemoryProvider
	executor    *execution.DemoExecutor
	audit       *audit.Chain
	idempotency *idempotency.Store
	grants      map[string]delegation.Grant
	invocations map[string]*record
	now         func() time.Time
	counter     int64
}

type record struct {
	Request              invocation.Request
	Hash                 string
	Tool                 tools.Definition
	Risk                 risk.Result
	Policy               policy.Decision
	Response             invocation.Response
	BudgetReservationID  string
	ReconciliationNeeded bool
}

func NewDemoEngine() (*Engine, error) {
	registry, err := tools.SeedDemoRegistry()
	if err != nil {
		return nil, err
	}
	credentialProvider := credentials.NewMemoryProvider()
	engine := &Engine{
		registry:    registry,
		policy:      policy.NewLocalEvaluator(),
		budgets:     budget.NewLedger(),
		limits:      ratelimit.NewLimiter(),
		approvals:   approval.NewStore(),
		credentials: credentialProvider,
		executor:    execution.NewDemoExecutor(credentialProvider),
		audit:       audit.NewChain(),
		idempotency: idempotency.NewStore(),
		grants:      seedDelegations(),
		invocations: make(map[string]*record),
		now:         func() time.Time { return time.Now().UTC() },
	}
	if err := engine.budgets.UpsertAccount(budget.Account{TenantID: "tenant_acme", ID: "budget_refunds_july", ScopeType: "agent", ScopeID: "agent_refund_assistant", Currency: "INR", LimitMinor: 10_000_000}); err != nil {
		return nil, err
	}
	engine.limits.SetRule("tenant_acme:agent_refund_assistant:messaging.send_email", ratelimit.Rule{Limit: 3, Window: time.Minute, Strict: true})
	return engine, nil
}

func (e *Engine) ListTools(tenantID string, scopes []string) []tools.Definition {
	return e.registry.List(tenantID, scopes)
}

func (e *Engine) Submit(ctx context.Context, req invocation.Request) (invocation.Response, error) {
	if req.InvocationID == "" {
		req.InvocationID = e.nextID("inv")
	}
	if req.RequestContext.RequestedAt.IsZero() {
		req.RequestContext.RequestedAt = e.now()
	}
	if req.Protocol == "" {
		req.Protocol = invocation.ProtocolREST
	}
	tool, err := e.registry.Get(req.TenantID, req.Tool.ID)
	if err != nil {
		return e.deny(req, "UNKNOWN_TOOL"), nil
	}
	if req.Tool.SchemaHash != "" && req.Tool.SchemaHash != tool.SchemaHash {
		return e.deny(req, "TOOL_SCHEMA_HASH_MISMATCH"), nil
	}
	req.Tool.SchemaVersion = tool.SchemaVersion
	req.Tool.SchemaHash = tool.SchemaHash

	hash, err := req.CanonicalHash()
	if err != nil {
		return invocation.Response{}, err
	}
	idempotencyRecord, replay, err := e.idempotency.Begin(req.TenantID, req.Tool.ID, req.Action, req.IdempotencyKey, hash)
	if err != nil {
		if errors.Is(err, idempotency.ErrConflict) {
			return e.deny(req, "IDEMPOTENCY_KEY_CONFLICT"), nil
		}
		return invocation.Response{}, err
	}
	if replay && idempotencyRecord.Completed {
		return idempotencyRecord.Response, nil
	}

	resp, rec, err := e.evaluate(ctx, req, tool, hash)
	if err != nil {
		return invocation.Response{}, err
	}
	e.mu.Lock()
	e.invocations[req.InvocationID] = rec
	e.mu.Unlock()
	e.idempotency.Complete(idempotencyRecord, resp)
	return resp, nil
}

func (e *Engine) GetInvocation(tenantID, invocationID string) (invocation.Response, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, ok := e.invocations[tenantID+"\x00"+invocationID]
	if !ok {
		rec, ok = e.invocations[invocationID]
	}
	if !ok || rec.Request.TenantID != tenantID {
		return invocation.Response{}, false
	}
	return rec.Response, true
}

func (e *Engine) Approve(ctx context.Context, tenantID, approvalID string, approver authn.Subject, reason string) (invocation.Response, error) {
	approvalRequest, err := e.approvals.Approve(tenantID, approvalID, approver, reason)
	if err != nil {
		return invocation.Response{}, err
	}
	e.mu.Lock()
	rec := e.findByInvocationLocked(tenantID, approvalRequest.InvocationID)
	e.mu.Unlock()
	if rec == nil {
		return invocation.Response{}, errors.New("invocation not found")
	}
	if approvalRequest.State != approval.StateApproved {
		resp := rec.Response
		resp.State = approval.InvocationStateForApproval(approvalRequest.State)
		resp.UpdatedAt = e.now()
		e.updateRecord(rec, resp)
		return resp, nil
	}
	// Approval is not authorization: repeat material checks before execution.
	currentTool, err := e.registry.Get(rec.Request.TenantID, rec.Request.Tool.ID)
	if err != nil || currentTool.SchemaHash != rec.Request.Tool.SchemaHash {
		resp := e.response(rec.Request.InvocationID, invocation.StateDenied, invocation.DecisionDeny, []string{"STALE_APPROVAL_TOOL_CHANGED"}, "", nil)
		e.updateRecord(rec, resp)
		return resp, nil
	}
	result, err := e.executeAllowed(ctx, rec.Request, rec.Tool, rec.Risk, rec.Policy)
	if err != nil {
		return invocation.Response{}, err
	}
	e.updateRecord(rec, result)
	return result, nil
}

func (e *Engine) Reject(tenantID, approvalID string, approver authn.Subject, reason string) (invocation.Response, error) {
	approvalRequest, err := e.approvals.Reject(tenantID, approvalID, approver, reason)
	if err != nil {
		return invocation.Response{}, err
	}
	e.mu.Lock()
	rec := e.findByInvocationLocked(tenantID, approvalRequest.InvocationID)
	e.mu.Unlock()
	if rec == nil {
		return invocation.Response{}, errors.New("invocation not found")
	}
	resp := e.response(rec.Request.InvocationID, invocation.StateDenied, invocation.DecisionDeny, []string{"APPROVAL_REJECTED"}, approvalID, nil)
	e.updateRecord(rec, resp)
	return resp, nil
}

func (e *Engine) AuditEvents(tenantID string) []audit.Event {
	return e.audit.Events(tenantID)
}

func (e *Engine) PendingApprovals(tenantID string) []approval.Request {
	return e.approvals.ListPending(tenantID)
}

func (e *Engine) VerifyAudit(tenantID string) error {
	return audit.Verify(e.audit.Events(tenantID))
}

func (e *Engine) evaluate(ctx context.Context, req invocation.Request, tool tools.Definition, hash string) (invocation.Response, *record, error) {
	rec := &record{Request: req, Hash: hash, Tool: tool}
	if err := tools.ValidateInput(tool, req.Arguments); err != nil {
		resp := e.response(req.InvocationID, invocation.StateDenied, invocation.DecisionDeny, []string{"TOOL_SCHEMA_VALIDATION_FAILED"}, "", nil)
		rec.Response = resp
		return resp, rec, nil
	}
	grant, ok := e.grants[req.TenantID+"\x00"+req.DelegationID]
	if !ok {
		resp := e.response(req.InvocationID, invocation.StateDenied, invocation.DecisionDeny, []string{"DELEGATION_NOT_FOUND"}, "", nil)
		rec.Response = resp
		return resp, rec, nil
	}
	delegationRequest := delegation.Request{
		TenantID: req.TenantID, AgentID: req.Agent.ID, ToolID: req.Tool.ID,
		Resource: req.Resource.Type + ":" + req.Resource.ID, Purpose: req.Purpose,
		Audience: "aegis", DelegationDepth: 1, Arguments: req.Arguments, Now: e.now(),
	}
	if err := delegation.ValidateGrant(grant, delegationRequest); err != nil {
		resp := e.response(req.InvocationID, invocation.StateDenied, invocation.DecisionDeny, []string{"DELEGATION_VALIDATION_FAILED"}, "", nil)
		rec.Response = resp
		return resp, rec, nil
	}
	riskResult := risk.Calculate(req, tool, risk.Context{HourUTC: e.now().UTC().Hour()})
	rec.Risk = riskResult
	decision, err := e.policy.Evaluate(req, tool, riskResult)
	if err != nil {
		decision = policy.FailClosedDecision(err)
	}
	rec.Policy = decision
	if decision.Decision == invocation.DecisionDeny {
		resp := e.response(req.InvocationID, invocation.StateDenied, invocation.DecisionDeny, decision.ReasonCodes, "", nil)
		rec.Response = resp
		return resp, rec, nil
	}
	if decision.Decision == invocation.DecisionRequireApproval {
		approvalRequest := e.approvals.Create(req.TenantID, req.InvocationID, req.Subject.ID, req.Agent.OwnerID, decision.Approval.RequiredApprovals, decision.Approval.RequiredGroup, decision.Approval.RequesterMayApprove, decision.Approval.ExpiresIn)
		resp := e.response(req.InvocationID, invocation.StatePendingApproval, invocation.DecisionRequireApproval, decision.ReasonCodes, approvalRequest.ID, nil)
		rec.Response = resp
		_, _ = e.audit.Append(req.TenantID, req.InvocationID, "APPROVAL_REQUESTED", "agent", req.Agent.ID, firstReason(decision.ReasonCodes), map[string]any{"approval_request_id": approvalRequest.ID})
		return resp, rec, nil
	}
	resp, err := e.executeAllowed(ctx, req, tool, riskResult, decision)
	rec.Response = resp
	return resp, rec, err
}

func (e *Engine) executeAllowed(ctx context.Context, req invocation.Request, tool tools.Definition, riskResult risk.Result, decision policy.Decision) (invocation.Response, error) {
	amount := req.AmountMinor()
	var reservation budget.Reservation
	var err error
	if amount > 0 && tool.SideEffect == tools.SideEffectFinancial {
		reservation, err = e.budgets.Reserve(req.TenantID, "budget_refunds_july", req.InvocationID, stringCurrency(req.Arguments["currency"]), amount)
		if err != nil {
			return e.response(req.InvocationID, invocation.StateDenied, invocation.DecisionDeny, []string{"BUDGET_RESERVATION_FAILED"}, "", nil), nil
		}
	}
	rateKey := req.TenantID + ":" + req.Agent.ID + ":" + tool.ID
	if _, err := e.limits.Check(rateKey); err != nil {
		if reservation.ID != "" {
			_ = e.budgets.Release(reservation.ID)
		}
		return e.response(req.InvocationID, invocation.StateDenied, invocation.DecisionDeny, []string{"RATE_LIMIT_EXCEEDED"}, "", nil), nil
	}
	scope := credentials.Scope{TenantID: req.TenantID, ToolID: tool.ID, Action: req.Action, Resource: req.Resource.Type + ":" + req.Resource.ID, AmountMinor: amount}
	credential, err := e.credentials.Issue(scope, 2*time.Minute)
	if err != nil {
		if reservation.ID != "" {
			_ = e.budgets.Release(reservation.ID)
		}
		return e.response(req.InvocationID, invocation.StateDenied, invocation.DecisionDeny, []string{"CREDENTIAL_ISSUANCE_FAILED"}, "", nil), nil
	}
	result, err := e.executor.Execute(ctx, req, tool, credential)
	if errors.Is(err, execution.ErrUnknownOutcome) || result.Outcome == execution.OutcomeUnknown {
		resp := e.response(req.InvocationID, invocation.StateReconciliationRequired, invocation.DecisionAllow, []string{"DOWNSTREAM_OUTCOME_UNKNOWN"}, "", result.Output)
		_, _ = e.audit.Append(req.TenantID, req.InvocationID, "RECONCILIATION_REQUIRED", "agent", req.Agent.ID, "DOWNSTREAM_OUTCOME_UNKNOWN", map[string]any{"tool_id": tool.ID})
		return resp, nil
	}
	if err != nil || result.Outcome == execution.OutcomeFailed {
		if reservation.ID != "" {
			_ = e.budgets.Release(reservation.ID)
		}
		resp := e.response(req.InvocationID, invocation.StateFailed, invocation.DecisionAllow, []string{"DOWNSTREAM_EXECUTION_FAILED"}, "", nil)
		_, _ = e.audit.Append(req.TenantID, req.InvocationID, "INVOCATION_FAILED", "agent", req.Agent.ID, "DOWNSTREAM_EXECUTION_FAILED", map[string]any{"tool_id": tool.ID})
		return resp, nil
	}
	if err := tools.ValidateOutput(tool, result.Output); err != nil {
		if reservation.ID != "" {
			_ = e.budgets.Release(reservation.ID)
		}
		return e.response(req.InvocationID, invocation.StateFailed, invocation.DecisionAllow, []string{"TOOL_OUTPUT_SCHEMA_VALIDATION_FAILED"}, "", nil), nil
	}
	if reservation.ID != "" {
		_ = e.budgets.Commit(reservation.ID)
	}
	resp := e.response(req.InvocationID, invocation.StateSucceeded, invocation.DecisionAllow, decision.ReasonCodes, "", result.Output)
	_, _ = e.audit.Append(req.TenantID, req.InvocationID, "INVOCATION_SUCCEEDED", "agent", req.Agent.ID, firstReason(decision.ReasonCodes), map[string]any{"tool_id": tool.ID, "risk_score": riskResult.Score})
	return resp, nil
}

func (e *Engine) deny(req invocation.Request, reason string) invocation.Response {
	resp := e.response(req.InvocationID, invocation.StateDenied, invocation.DecisionDeny, []string{reason}, "", nil)
	_, _ = e.audit.Append(req.TenantID, req.InvocationID, "INVOCATION_DENIED", "agent", req.Agent.ID, reason, map[string]any{"tool_id": req.Tool.ID})
	return resp
}

func (e *Engine) response(id string, state invocation.State, decision invocation.Decision, reasons []string, approvalID string, result map[string]any) invocation.Response {
	now := e.now()
	return invocation.Response{
		ID: id, State: state, Decision: decision, ReasonCodes: reasons, ApprovalRequestID: approvalID,
		Result: result, CreatedAt: now, UpdatedAt: now,
		Links: map[string]any{"self": "/v1/invocations/" + id},
	}
}

func (e *Engine) updateRecord(rec *record, resp invocation.Response) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rec.Response = resp
	e.invocations[rec.Request.InvocationID] = rec
	e.invocations[rec.Request.TenantID+"\x00"+rec.Request.InvocationID] = rec
}

func (e *Engine) findByInvocationLocked(tenantID, invocationID string) *record {
	if rec, ok := e.invocations[tenantID+"\x00"+invocationID]; ok {
		return rec
	}
	if rec, ok := e.invocations[invocationID]; ok && rec.Request.TenantID == tenantID {
		return rec
	}
	return nil
}

func (e *Engine) nextID(prefix string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.counter++
	return fmt.Sprintf("%s_%06d", prefix, e.counter)
}

func firstReason(reasons []string) string {
	if len(reasons) == 0 {
		return "OK"
	}
	return reasons[0]
}

func stringCurrency(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return "INR"
}

func seedDelegations() map[string]delegation.Grant {
	now := time.Now().UTC()
	maxRefund := int64(10_000_000)
	maxAuto := int64(1_000_000)
	return map[string]delegation.Grant{
		"tenant_acme\x00dlg_789": {
			ID: "dlg_789", TenantID: "tenant_acme", GrantorSubjectID: "user_123", GranteeAgentID: "agent_refund_assistant",
			AllowedTools: []string{"payments.refund", "payments.get_refund", "crm.get_customer", "crm.export_customers", "messaging.send_email"},
			AllowedResources: []string{"customer:CUST-1042", "tenant:tenant_acme"},
			ArgumentConstraints: delegation.ArgumentConstraints{
				Currencies: []string{"INR"}, MaxAmountMinor: &maxRefund,
				RequiredFields: []string{}, RejectUnknown: false,
			},
			Purpose: "customer_support", Audience: "aegis", MaxDelegationDepth: 1, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour),
		},
		"tenant_acme\x00dlg_auto_refund": {
			ID: "dlg_auto_refund", TenantID: "tenant_acme", GrantorSubjectID: "user_123", GranteeAgentID: "agent_refund_assistant",
			AllowedTools: []string{"payments.refund"}, AllowedResources: []string{"customer:CUST-1042"},
			ArgumentConstraints: delegation.ArgumentConstraints{Currencies: []string{"INR"}, MaxAmountMinor: &maxAuto, RejectUnknown: false},
			Purpose: "customer_support", Audience: "aegis", MaxDelegationDepth: 1, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour),
		},
	}
}
