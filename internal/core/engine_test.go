package core

import (
	"context"
	"testing"
	"time"

	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/policy"
	"github.com/aegis/aegis/internal/ratelimit"
	"github.com/aegis/aegis/internal/risk"
	"github.com/aegis/aegis/internal/tools"
)

func TestLowRiskRefundExecutesAutomatically(t *testing.T) {
	engine, err := NewDemoEngine()
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	resp, err := engine.Submit(context.Background(), baseRefundRequest("dlg_auto_refund", 500_00))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.State != invocation.StateSucceeded {
		t.Fatalf("expected success, got %#v", resp)
	}
}

func TestLargeRefundRequiresTwoApprovals(t *testing.T) {
	engine, err := NewDemoEngine()
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	resp, err := engine.Submit(context.Background(), baseRefundRequest("dlg_789", 5_000_000))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.State != invocation.StatePendingApproval {
		t.Fatalf("expected pending approval, got %#v", resp)
	}
	if _, err := engine.Approve(context.Background(), "tenant_acme", resp.ApprovalRequestID, authn.Subject{ID: "user_123", Groups: []string{"finance"}}, "self"); err == nil {
		t.Fatal("expected self approval to fail")
	}
	resp, err = engine.Approve(context.Background(), "tenant_acme", resp.ApprovalRequestID, authn.Subject{ID: "approver_finance_1", Groups: []string{"finance"}}, "approved")
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if resp.State != invocation.StatePendingApproval {
		t.Fatalf("expected still pending, got %#v", resp)
	}
	resp, err = engine.Approve(context.Background(), "tenant_acme", resp.ApprovalRequestID, authn.Subject{ID: "approver_finance_2", Groups: []string{"finance"}}, "approved")
	if err != nil {
		t.Fatalf("second approval: %v", err)
	}
	if resp.State != invocation.StateSucceeded {
		t.Fatalf("expected execution after second approval, got %#v", resp)
	}
}

func TestIdempotentReplayReturnsSameResultAndPoisoningFails(t *testing.T) {
	engine, _ := NewDemoEngine()
	req := baseRefundRequest("dlg_auto_refund", 500_00)
	req.IdempotencyKey = "same-key"
	first, err := engine.Submit(context.Background(), req)
	if err != nil {
		t.Fatalf("first submit: %v", err)
	}
	second, err := engine.Submit(context.Background(), req)
	if err != nil {
		t.Fatalf("second submit: %v", err)
	}
	if first.Result["refund_id"] != second.Result["refund_id"] {
		t.Fatalf("expected replay result, got %#v %#v", first.Result, second.Result)
	}
	req.Arguments["amount_minor"] = int64(600_00)
	conflict, err := engine.Submit(context.Background(), req)
	if err != nil {
		t.Fatalf("conflict submit: %v", err)
	}
	if conflict.State != invocation.StateDenied || conflict.ReasonCodes[0] != "IDEMPOTENCY_KEY_CONFLICT" {
		t.Fatalf("expected idempotency conflict, got %#v", conflict)
	}
}

func TestCrossTenantRequestIsDenied(t *testing.T) {
	engine, _ := NewDemoEngine()
	req := baseRefundRequest("dlg_auto_refund", 500_00)
	req.Resource.OwnerTenantID = "tenant_globex"
	resp, err := engine.Submit(context.Background(), req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.State != invocation.StateDenied {
		t.Fatalf("expected denial, got %#v", resp)
	}
}

func TestUnknownOutcomeReconcilesWithoutDuplicateRefund(t *testing.T) {
	engine, _ := NewDemoEngine()
	req := baseRefundRequest("dlg_auto_refund", 500_00)
	req.IdempotencyKey = "unknown-outcome"
	req.Arguments["simulate"] = "unknown_outcome"
	resp, err := engine.Submit(context.Background(), req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.State != invocation.StateReconciliationRequired {
		t.Fatalf("expected reconciliation required, got %#v", resp)
	}
	reconciled, err := engine.Reconcile(context.Background(), "tenant_acme", resp.ID)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if reconciled.State != invocation.StateSucceeded {
		t.Fatalf("expected reconciliation success, got %#v", reconciled)
	}
	replay, err := engine.Submit(context.Background(), req)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.Result["refund_id"] != reconciled.Result["refund_id"] {
		t.Fatalf("expected reconciled result to be idempotent, got %#v %#v", replay.Result, reconciled.Result)
	}
}

func TestAuditRootGeneratedAfterEvents(t *testing.T) {
	engine, _ := NewDemoEngine()
	resp, err := engine.Submit(context.Background(), baseRefundRequest("dlg_auto_refund", 500_00))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.State != invocation.StateSucceeded {
		t.Fatalf("expected success, got %#v", resp)
	}
	root, err := engine.AuditRoot("tenant_acme")
	if err != nil {
		t.Fatalf("audit root: %v", err)
	}
	if root.RootHash == "" || root.Signature == "" {
		t.Fatalf("invalid root: %#v", root)
	}
}

func TestSchemaChangeInvalidatesApproval(t *testing.T) {
	engine, _ := NewDemoEngine()
	resp, err := engine.Submit(context.Background(), baseRefundRequest("dlg_789", 5_000_000))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	def := tools.DemoDefinitions()[0]
	def.SchemaVersion = 2
	def.InputSchema["properties"].(map[string]any)["new_required"] = map[string]any{"type": "string"}
	if _, err := engine.RegisterTool(def); err != nil {
		t.Fatalf("register schema change: %v", err)
	}
	_, _ = engine.Approve(context.Background(), "tenant_acme", resp.ApprovalRequestID, authn.Subject{ID: "approver_finance_1", Groups: []string{"finance"}}, "approved")
	final, err := engine.Approve(context.Background(), "tenant_acme", resp.ApprovalRequestID, authn.Subject{ID: "approver_finance_2", Groups: []string{"finance"}}, "approved")
	if err != nil {
		t.Fatalf("second approval: %v", err)
	}
	if final.State != invocation.StateDenied || final.ReasonCodes[0] != "STALE_APPROVAL_TOOL_CHANGED" {
		t.Fatalf("expected stale schema denial, got %#v", final)
	}
}

func TestPolicyReevaluationAfterApprovalCanDeny(t *testing.T) {
	engine, _ := NewDemoEngine()
	resp, err := engine.Submit(context.Background(), baseRefundRequest("dlg_789", 5_000_000))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	engine.SetPolicyEvaluator(denyEvaluator{})
	_, _ = engine.Approve(context.Background(), "tenant_acme", resp.ApprovalRequestID, authn.Subject{ID: "approver_finance_1", Groups: []string{"finance"}}, "approved")
	final, err := engine.Approve(context.Background(), "tenant_acme", resp.ApprovalRequestID, authn.Subject{ID: "approver_finance_2", Groups: []string{"finance"}}, "approved")
	if err != nil {
		t.Fatalf("second approval: %v", err)
	}
	if final.State != invocation.StateDenied || final.ReasonCodes[0] != "POST_APPROVAL_POLICY_DENIED" {
		t.Fatalf("expected post-approval policy denial, got %#v", final)
	}
}

func TestPolicyUnavailableFailsClosed(t *testing.T) {
	engine, _ := NewDemoEngine()
	engine.SetPolicyEvaluator(policy.FailingEvaluator{})
	resp, err := engine.Submit(context.Background(), baseRefundRequest("dlg_auto_refund", 500_00))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.State != invocation.StateDenied || resp.ReasonCodes[0] != "POLICY_UNAVAILABLE_FAIL_CLOSED" {
		t.Fatalf("expected fail-closed policy denial, got %#v", resp)
	}
}

func TestDistributedRateLimiterFailsClosed(t *testing.T) {
	engine, _ := NewDemoEngine()
	engine.limits.SetRule("tenant_acme:agent_refund_assistant:payments.refund", ratelimit.Rule{Limit: 1, Window: time.Minute, Strict: true})
	engine.SetDistributedRateLimiter(ratelimit.RedisLimiter{Addr: "127.0.0.1:1", Timeout: 10 * time.Millisecond})
	resp, err := engine.Submit(context.Background(), baseRefundRequest("dlg_auto_refund", 500_00))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.State != invocation.StateDenied || resp.ReasonCodes[0] != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("expected fail-closed rate-limit denial, got %#v", resp)
	}
}

type denyEvaluator struct{}

func (denyEvaluator) Evaluate(invocation.Request, tools.Definition, risk.Result) (policy.Decision, error) {
	return policy.Decision{Allow: false, Decision: invocation.DecisionDeny, ReasonCodes: []string{"POLICY_CHANGED_TO_DENY"}, PolicyHash: "sha256:deny", PolicyVer: "test-deny"}, nil
}

func baseRefundRequest(delegationID string, amount int64) invocation.Request {
	return invocation.Request{
		TenantID: "tenant_acme", Protocol: invocation.ProtocolREST, IdempotencyKey: "refund-key", DelegationID: delegationID,
		Subject: authn.Subject{Type: authn.PrincipalHuman, ID: "user_123", Groups: []string{"support"}, Roles: []string{"refund_operator"}},
		Agent: authn.Agent{ID: "agent_refund_assistant", TrustLevel: 3, OwnerID: "user_123", ClientID: "refund-agent-client"},
		Tool: invocation.ToolRef{ID: "payments.refund"}, Action: "refund",
		Resource: invocation.Resource{Type: "customer", ID: "CUST-1042", OwnerTenantID: "tenant_acme"},
		Purpose: "customer_support",
		Arguments: map[string]any{"customer_id": "CUST-1042", "amount_minor": amount, "currency": "INR", "reason": "duplicate_charge"},
	}
}
