package policy

import (
	"testing"

	"github.com/aegis/aegis/internal/invocation"
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
