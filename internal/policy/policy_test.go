package policy

import (
	"errors"
	"testing"

	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/risk"
	"github.com/aegis/aegis/internal/tools"
)

func TestLocalEvaluatorRequiresApprovalForLargeRefund(t *testing.T) {
	evaluator := NewLocalEvaluator()
	tool := tools.DemoDefinitions()[0]
	req := invocation.Request{
		TenantID: "tenant_acme",
		Agent: authn.Agent{ID: "agent_refund_assistant", TrustLevel: 3},
		Resource: invocation.Resource{Type: "customer", ID: "CUST-1042", OwnerTenantID: "tenant_acme"},
		Arguments: map[string]any{"amount_minor": int64(5_000_000)},
	}

	decision, err := evaluator.Evaluate(req, tool, risk.Result{Score: 78})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	if decision.Decision != invocation.DecisionRequireApproval {
		t.Fatalf("expected approval decision, got %#v", decision)
	}
	if decision.Approval == nil || decision.Approval.RequiredApprovals != 2 {
		t.Fatalf("expected two approval obligation, got %#v", decision.Approval)
	}
}

func TestLocalEvaluatorDeniesCrossTenantResource(t *testing.T) {
	evaluator := NewLocalEvaluator()
	tool := tools.DemoDefinitions()[0]
	req := invocation.Request{
		TenantID: "tenant_acme",
		Resource: invocation.Resource{Type: "customer", ID: "CUST-9999", OwnerTenantID: "tenant_globex"},
		Arguments: map[string]any{"amount_minor": int64(500_00)},
	}

	decision, err := evaluator.Evaluate(req, tool, risk.Result{Score: 20})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	if decision.Allow {
		t.Fatalf("expected cross-tenant denial, got %#v", decision)
	}
}

func TestFailClosedDecisionIncludesDecisionID(t *testing.T) {
	decision := FailClosedDecision(errors.New("opa unavailable"))
	if decision.Decision != invocation.DecisionDeny || decision.DecisionID == "" {
		t.Fatalf("expected traceable fail-closed denial, got %#v", decision)
	}
}
