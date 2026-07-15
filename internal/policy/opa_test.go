package policy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/risk"
	"github.com/aegis/aegis/internal/tools"
)

func TestOPAEvaluatorParsesStructuredDecision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode opa request: %v", err)
		}
		delegation, _ := body["input"]["delegation"].(map[string]any)
		if delegation["valid"] != true {
			t.Fatalf("expected pre-validated delegation fact, got %#v", body["input"]["delegation"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"allow":false,"decision":"REQUIRE_APPROVAL","reason_codes":["OPA_APPROVAL"],"approval":{"required_approvals":2,"required_group":"finance","requester_may_approve":false,"expires_in_seconds":3600}}}`))
	}))
	defer server.Close()

	evaluator := OPAEvaluator{BaseURL: server.URL, DecisionPath: "aegis/authz/decision", PolicyHash: "sha256:test", PolicyVersion: "bundle-v1"}
	decision, err := evaluator.Evaluate(invocation.Request{DelegationID: "dlg_1"}, tools.Definition{Active: true}, risk.Result{})
	if err != nil {
		t.Fatalf("evaluate opa: %v", err)
	}
	if decision.Decision != invocation.DecisionRequireApproval || decision.DecisionID == "" || decision.Approval == nil {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if decision.Approval.RequiredApprovals != 2 || decision.Approval.ExpiresIn != time.Hour {
		t.Fatalf("unexpected approval obligation: %#v", decision.Approval)
	}
}

func TestOPAEvaluatorFailsClosedOnUnavailableOPA(t *testing.T) {
	evaluator := OPAEvaluator{BaseURL: "http://127.0.0.1:1", DecisionPath: "aegis/authz/decision"}
	_, err := evaluator.Evaluate(invocation.Request{}, tools.Definition{}, risk.Result{})
	if err == nil {
		t.Fatal("expected OPA failure")
	}
	decision := FailClosedDecision(err)
	if decision.Allow || decision.Decision != invocation.DecisionDeny {
		t.Fatalf("expected fail closed decision, got %#v", decision)
	}
}
