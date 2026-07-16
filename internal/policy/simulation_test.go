package policy

import (
	"testing"

	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/risk"
	"github.com/aegis/aegis/internal/tools"
)

func TestCompareDecisionsFlagsApprovalToAllow(t *testing.T) {
	result := CompareDecisions(
		Decision{Decision: invocation.DecisionRequireApproval, Redactions: []string{"credential"}},
		Decision{Decision: invocation.DecisionAllow, Redactions: []string{"credential"}},
	)
	if !result.Dangerous || result.Findings[0] != "APPROVAL_TO_ALLOW" {
		t.Fatalf("expected dangerous approval widening, got %#v", result)
	}
}

func TestCompareDecisionsFlagsRedactionRemoval(t *testing.T) {
	result := CompareDecisions(
		Decision{Decision: invocation.DecisionDeny, Redactions: []string{"credential", "restricted_fields"}},
		Decision{Decision: invocation.DecisionDeny, Redactions: []string{"credential"}},
	)
	if !result.Dangerous {
		t.Fatalf("expected redaction removal, got %#v", result)
	}
}

func TestEvaluateBundleSimulationUsesMetadataThreshold(t *testing.T) {
	req := replayRefundRequest(2_000_000)
	tool := replayRefundTool()
	baseline := EvaluateBundleSimulation(req, tool, risk.Result{Score: 30}, BundleSimulationConfig{
		Version: "local-policy-v1",
		Hash:    "sha256:baseline",
	})
	proposed := EvaluateBundleSimulation(req, tool, risk.Result{Score: 30}, BundleSimulationConfig{
		Version:  "candidate-demo",
		Hash:     "sha256:proposed",
		Metadata: map[string]any{"approval_threshold_minor": float64(10_000_000), "risk_approval_score": float64(101)},
	})
	result := CompareDecisions(baseline, proposed)
	if baseline.Decision != invocation.DecisionRequireApproval {
		t.Fatalf("expected baseline to require approval, got %#v", baseline)
	}
	if proposed.Decision != invocation.DecisionAllow {
		t.Fatalf("expected proposed bundle to allow, got %#v", proposed)
	}
	if !result.Dangerous || result.Findings[0] != "APPROVAL_TO_ALLOW" {
		t.Fatalf("expected approval-to-allow finding, got %#v", result)
	}
}

func TestEvaluateBundleSimulationCanDetectCredentialScopeWidening(t *testing.T) {
	req := replayRefundRequest(500)
	tool := replayRefundTool()
	baseline := EvaluateBundleSimulation(req, tool, risk.Result{Score: 10}, BundleSimulationConfig{
		Version: "local-policy-v1",
		Hash:    "sha256:baseline",
	})
	proposed := EvaluateBundleSimulation(req, tool, risk.Result{Score: 10}, BundleSimulationConfig{
		Version:  "candidate-wide-credential",
		Hash:     "sha256:proposed",
		Metadata: map[string]any{"credential_scope_wildcard": true},
	})
	result := CompareDecisions(baseline, proposed)
	if !result.Dangerous || result.Findings[0] != "CREDENTIAL_SCOPE_WIDENING" {
		t.Fatalf("expected credential widening finding, got %#v", result)
	}
}

func replayRefundRequest(amount int64) invocation.Request {
	return invocation.Request{
		InvocationID: "inv_replay",
		TenantID:     "tenant_acme",
		Subject:      authn.Subject{Type: authn.PrincipalHuman, ID: "user_123"},
		Agent:        authn.Agent{ID: "agent_refund_assistant", TrustLevel: 3, OwnerID: "user_123", ClientID: "refund-agent-client"},
		Tool:         invocation.ToolRef{ID: "payments.refund", SchemaVersion: 1, SchemaHash: "sha256:schema"},
		Action:       "refund",
		Resource:     invocation.Resource{Type: "customer", ID: "CUST-1042", OwnerTenantID: "tenant_acme"},
		Purpose:      "customer_support",
		Arguments:    map[string]any{"amount_minor": amount, "currency": "INR"},
	}
}

func replayRefundTool() tools.Definition {
	return tools.Definition{
		TenantID:                   "tenant_acme",
		ID:                         "payments.refund",
		RequiredCredentialTemplate: "payments-refund-scoped",
		Active:                     true,
		ApprovalDefaults:           tools.ApprovalDefaults{RequiredApprovals: 2, RequiredGroup: "finance", AmountThresholdMinor: 1_000_000},
	}
}
