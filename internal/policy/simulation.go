package policy

import (
	"reflect"
	"slices"

	"github.com/aegis/aegis/internal/invocation"
)

type SimulationResult struct {
	Dangerous      bool     `json:"dangerous"`
	Findings       []string `json:"findings"`
	BaselineID     string   `json:"baseline_decision_id"`
	ProposedID     string   `json:"proposed_decision_id"`
	BaselineAction invocation.Decision `json:"baseline_decision"`
	ProposedAction invocation.Decision `json:"proposed_decision"`
}

func CompareDecisions(baseline, proposed Decision) SimulationResult {
	result := SimulationResult{
		BaselineID: baseline.DecisionID, ProposedID: proposed.DecisionID,
		BaselineAction: baseline.Decision, ProposedAction: proposed.Decision,
	}
	add := func(code string) {
		result.Dangerous = true
		result.Findings = append(result.Findings, code)
	}
	if baseline.Decision == invocation.DecisionRequireApproval && proposed.Decision == invocation.DecisionAllow {
		add("APPROVAL_TO_ALLOW")
	}
	if baseline.Decision == invocation.DecisionDeny && proposed.Decision == invocation.DecisionAllow {
		add("DENY_TO_ALLOW")
	}
	if baseline.Credential != nil && proposed.Credential != nil {
		if scopeWidened(baseline.Credential.Scope, proposed.Credential.Scope) {
			add("CREDENTIAL_SCOPE_WIDENING")
		}
	}
	for _, redaction := range baseline.Redactions {
		if !slices.Contains(proposed.Redactions, redaction) {
			add("REDACTION_REMOVAL")
		}
	}
	return result
}

func scopeWidened(baseline, proposed map[string]any) bool {
	for key, baselineValue := range baseline {
		proposedValue, ok := proposed[key]
		if !ok {
			return true
		}
		if !reflect.DeepEqual(proposedValue, baselineValue) {
			if proposedString, ok := proposedValue.(string); ok && (proposedString == "*" || proposedString == "") {
				return true
			}
		}
	}
	return false
}
