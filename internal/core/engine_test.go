package core

import (
	"context"
	"testing"

	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/invocation"
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
