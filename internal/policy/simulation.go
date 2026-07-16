package policy

import (
	"encoding/json"
	"reflect"
	"slices"
	"time"

	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/risk"
	"github.com/aegis/aegis/internal/tools"
)

type SimulationResult struct {
	Dangerous      bool     `json:"dangerous"`
	Findings       []string `json:"findings"`
	BaselineID     string   `json:"baseline_decision_id"`
	ProposedID     string   `json:"proposed_decision_id"`
	BaselineAction invocation.Decision `json:"baseline_decision"`
	ProposedAction invocation.Decision `json:"proposed_decision"`
}

type BundleSimulationConfig struct {
	Version  string
	Hash     string
	Metadata map[string]any
}

func EvaluateBundleSimulation(req invocation.Request, tool tools.Definition, riskResult risk.Result, cfg BundleSimulationConfig) Decision {
	if cfg.Version == "" {
		cfg.Version = LocalPolicyVersion
	}
	if cfg.Metadata == nil {
		cfg.Metadata = map[string]any{}
	}
	if cfg.Hash == "" {
		cfg.Hash = NewLocalEvaluator().Hash
	}
	now := req.RequestContext.RequestedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	decision := Decision{
		Allow:       false,
		Decision:    invocation.DecisionDeny,
		ReasonCodes: []string{"DEFAULT_DENY"},
		PolicyHash:  cfg.Hash,
		PolicyVer:   cfg.Version,
		EvaluatedAt: now.UTC(),
	}

	tool.Active = metadataBool(cfg.Metadata, "tool_active", tool.Active)
	tool.ApprovalDefaults.AmountThresholdMinor = metadataInt64(cfg.Metadata, "approval_threshold_minor", tool.ApprovalDefaults.AmountThresholdMinor)
	tool.ApprovalDefaults.RequiredApprovals = metadataInt(cfg.Metadata, "required_approvals", tool.ApprovalDefaults.RequiredApprovals)
	tool.ApprovalDefaults.RequiredGroup = metadataString(cfg.Metadata, "required_group", tool.ApprovalDefaults.RequiredGroup)
	riskApprovalScore := metadataInt(cfg.Metadata, "risk_approval_score", 65)

	if !tool.Active {
		decision.ReasonCodes = []string{"TOOL_DISABLED"}
		return withID(decision)
	}
	if req.TenantID == "" || req.Resource.OwnerTenantID == "" || req.TenantID != req.Resource.OwnerTenantID {
		decision.ReasonCodes = []string{"TENANT_RESOURCE_MISMATCH"}
		return withID(decision)
	}
	decision.Credential = &CredentialObligation{
		Template: tool.RequiredCredentialTemplate,
		TTL:      2 * time.Minute,
		Scope: map[string]any{
			"tenant_id":    req.TenantID,
			"tool_id":      tool.ID,
			"action":       req.Action,
			"resource":     req.Resource.Type + ":" + req.Resource.ID,
			"amount_minor": req.AmountMinor(),
		},
	}
	if metadataBool(cfg.Metadata, "credential_scope_wildcard", false) {
		decision.Credential.Scope["resource"] = "*"
	}
	if resource := metadataString(cfg.Metadata, "credential_scope_resource", ""); resource != "" {
		decision.Credential.Scope["resource"] = resource
	}
	decision.Redactions = []string{"credential", "body", "restricted_fields"}
	if redactions := metadataStringSlice(cfg.Metadata, "redactions"); len(redactions) > 0 {
		decision.Redactions = redactions
	}
	for _, redaction := range metadataStringSlice(cfg.Metadata, "remove_redactions") {
		decision.Redactions = removeString(decision.Redactions, redaction)
	}

	if forced := invocation.Decision(metadataString(cfg.Metadata, "force_decision", "")); forced != "" {
		switch forced {
		case invocation.DecisionAllow:
			decision.Allow = true
			decision.Decision = invocation.DecisionAllow
			decision.ReasonCodes = []string{"POLICY_ALLOW"}
		case invocation.DecisionRequireApproval:
			decision.Allow = false
			decision.Decision = invocation.DecisionRequireApproval
			decision.ReasonCodes = []string{"POLICY_REQUIRES_APPROVAL"}
			decision.Approval = approvalObligationForTool(tool)
		default:
			decision.Allow = false
			decision.Decision = invocation.DecisionDeny
			decision.ReasonCodes = []string{"POLICY_DENY"}
		}
		return withID(decision)
	}

	if bundleRequiresApproval(req, tool, riskResult, riskApprovalScore) {
		decision.Allow = false
		decision.Decision = invocation.DecisionRequireApproval
		decision.ReasonCodes = bundleApprovalReasons(req, tool, riskResult, riskApprovalScore)
		decision.Approval = approvalObligationForTool(tool)
		return withID(decision)
	}

	decision.Allow = true
	decision.Decision = invocation.DecisionAllow
	decision.ReasonCodes = []string{"POLICY_ALLOW"}
	return withID(decision)
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

func bundleRequiresApproval(req invocation.Request, tool tools.Definition, riskResult risk.Result, riskApprovalScore int) bool {
	if tool.ApprovalDefaults.RequiredApprovals > 0 && tool.ApprovalDefaults.AmountThresholdMinor == 0 {
		return true
	}
	if tool.ApprovalDefaults.AmountThresholdMinor > 0 && req.AmountMinor() > tool.ApprovalDefaults.AmountThresholdMinor {
		return true
	}
	if riskApprovalScore > 0 && riskResult.Score >= riskApprovalScore {
		return true
	}
	return false
}

func bundleApprovalReasons(req invocation.Request, tool tools.Definition, riskResult risk.Result, riskApprovalScore int) []string {
	reasons := []string{}
	if tool.ApprovalDefaults.AmountThresholdMinor > 0 && req.AmountMinor() > tool.ApprovalDefaults.AmountThresholdMinor {
		reasons = append(reasons, "AMOUNT_REQUIRES_APPROVAL")
	}
	if riskApprovalScore > 0 && riskResult.Score >= riskApprovalScore {
		reasons = append(reasons, "HIGH_RISK_INVOCATION")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "TOOL_REQUIRES_APPROVAL")
	}
	return reasons
}

func approvalObligationForTool(tool tools.Definition) *ApprovalObligation {
	required := tool.ApprovalDefaults.RequiredApprovals
	if required <= 0 {
		required = 1
	}
	return &ApprovalObligation{
		RequiredApprovals:   required,
		RequiredGroup:       tool.ApprovalDefaults.RequiredGroup,
		RequesterMayApprove: false,
		ExpiresIn:           time.Hour,
		ReasonRequired:      true,
	}
}

func metadataString(metadata map[string]any, key, fallback string) string {
	value, ok := metadata[key]
	if !ok || value == nil {
		return fallback
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return fallback
	}
	return text
}

func metadataBool(metadata map[string]any, key string, fallback bool) bool {
	value, ok := metadata[key]
	if !ok || value == nil {
		return fallback
	}
	typed, ok := value.(bool)
	if !ok {
		return fallback
	}
	return typed
}

func metadataInt(metadata map[string]any, key string, fallback int) int {
	return int(metadataInt64(metadata, key, int64(fallback)))
}

func metadataInt64(metadata map[string]any, key string, fallback int64) int64 {
	value, ok := metadata[key]
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func metadataStringSlice(metadata map[string]any, key string) []string {
	value, ok := metadata[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return append([]string{}, typed...)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if ok && text != "" {
				values = append(values, text)
			}
		}
		return values
	default:
		return nil
	}
}

func removeString(values []string, target string) []string {
	result := values[:0]
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}
