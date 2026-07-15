package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aegis/aegis/internal/canonical"
	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/risk"
	"github.com/aegis/aegis/internal/tools"
)

const LocalPolicyVersion = "local-policy-v1"

type Decision struct {
	Allow       bool                  `json:"allow"`
	Decision    invocation.Decision   `json:"decision"`
	ReasonCodes []string              `json:"reason_codes"`
	Approval    *ApprovalObligation   `json:"approval,omitempty"`
	Credential  *CredentialObligation `json:"credential,omitempty"`
	Redactions  []string              `json:"redactions,omitempty"`
	PolicyHash  string                `json:"policy_hash"`
	PolicyVer   string                `json:"policy_version"`
	DecisionID  string                `json:"decision_id"`
	EvaluatedAt time.Time             `json:"evaluated_at"`
}

type ApprovalObligation struct {
	RequiredApprovals   int           `json:"required_approvals"`
	RequiredGroup       string        `json:"required_group"`
	RequesterMayApprove bool          `json:"requester_may_approve"`
	ExpiresIn           time.Duration `json:"expires_in"`
	ReasonRequired      bool          `json:"reason_required"`
}

func (o *ApprovalObligation) UnmarshalJSON(data []byte) error {
	var raw struct {
		RequiredApprovals   int           `json:"required_approvals"`
		RequiredGroup       string        `json:"required_group"`
		RequesterMayApprove bool          `json:"requester_may_approve"`
		ExpiresIn           time.Duration `json:"expires_in"`
		ExpiresInSeconds    int64         `json:"expires_in_seconds"`
		ReasonRequired      bool          `json:"reason_required"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	o.RequiredApprovals = raw.RequiredApprovals
	o.RequiredGroup = raw.RequiredGroup
	o.RequesterMayApprove = raw.RequesterMayApprove
	o.ExpiresIn = raw.ExpiresIn
	if o.ExpiresIn <= 0 && raw.ExpiresInSeconds > 0 {
		o.ExpiresIn = time.Duration(raw.ExpiresInSeconds) * time.Second
	}
	o.ReasonRequired = raw.ReasonRequired
	return nil
}

type CredentialObligation struct {
	Template string         `json:"template"`
	Scope    map[string]any `json:"scope"`
	TTL      time.Duration  `json:"ttl"`
}

type Evaluator interface {
	Evaluate(req invocation.Request, tool tools.Definition, risk risk.Result) (Decision, error)
}

type LocalEvaluator struct {
	Version string
	Hash    string
	Now     func() time.Time
}

func NewLocalEvaluator() LocalEvaluator {
	sum := sha256.Sum256([]byte(LocalPolicyVersion))
	return LocalEvaluator{
		Version: LocalPolicyVersion,
		Hash:    "sha256:" + hex.EncodeToString(sum[:]),
		Now:     func() time.Time { return time.Now().UTC() },
	}
}

func (e LocalEvaluator) Evaluate(req invocation.Request, tool tools.Definition, riskResult risk.Result) (Decision, error) {
	if e.Version == "" {
		e = NewLocalEvaluator()
	}
	now := e.Now()
	decision := Decision{
		Allow:       false,
		Decision:    invocation.DecisionDeny,
		ReasonCodes: []string{"DEFAULT_DENY"},
		PolicyHash:  e.Hash,
		PolicyVer:   e.Version,
		EvaluatedAt: now,
	}

	if !tool.Active {
		decision.ReasonCodes = []string{"TOOL_DISABLED"}
		return withID(decision), nil
	}
	if req.TenantID == "" || req.Resource.OwnerTenantID == "" || req.TenantID != req.Resource.OwnerTenantID {
		decision.ReasonCodes = []string{"TENANT_RESOURCE_MISMATCH"}
		return withID(decision), nil
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
	decision.Redactions = []string{"credential", "body", "restricted_fields"}

	if requiresApproval(req, tool, riskResult) {
		required := tool.ApprovalDefaults.RequiredApprovals
		if required <= 0 {
			required = 1
		}
		decision.Allow = false
		decision.Decision = invocation.DecisionRequireApproval
		decision.ReasonCodes = approvalReasons(req, tool, riskResult)
		decision.Approval = &ApprovalObligation{
			RequiredApprovals:   required,
			RequiredGroup:       tool.ApprovalDefaults.RequiredGroup,
			RequesterMayApprove: false,
			ExpiresIn:           time.Hour,
			ReasonRequired:      true,
		}
		return withID(decision), nil
	}

	decision.Allow = true
	decision.Decision = invocation.DecisionAllow
	decision.ReasonCodes = []string{"POLICY_ALLOW"}
	return withID(decision), nil
}

func requiresApproval(req invocation.Request, tool tools.Definition, riskResult risk.Result) bool {
	if tool.ApprovalDefaults.RequiredApprovals > 0 && tool.ApprovalDefaults.AmountThresholdMinor == 0 {
		return true
	}
	if tool.ApprovalDefaults.AmountThresholdMinor > 0 && req.AmountMinor() > tool.ApprovalDefaults.AmountThresholdMinor {
		return true
	}
	if riskResult.Score >= 65 {
		return true
	}
	return false
}

func approvalReasons(req invocation.Request, tool tools.Definition, riskResult risk.Result) []string {
	reasons := []string{}
	if tool.ApprovalDefaults.AmountThresholdMinor > 0 && req.AmountMinor() > tool.ApprovalDefaults.AmountThresholdMinor {
		reasons = append(reasons, "AMOUNT_REQUIRES_APPROVAL")
	}
	if riskResult.Score >= 65 {
		reasons = append(reasons, "HIGH_RISK_INVOCATION")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "TOOL_REQUIRES_APPROVAL")
	}
	return reasons
}

func withID(decision Decision) Decision {
	decision.DecisionID = decisionID(decision)
	return decision
}

func decisionID(decision Decision) string {
	payload := map[string]any{
		"allow":        decision.Allow,
		"decision":     decision.Decision,
		"reason_codes": decision.ReasonCodes,
		"policy_hash":  decision.PolicyHash,
		"policy_ver":   decision.PolicyVer,
		"evaluated_at": decision.EvaluatedAt.Format(time.RFC3339Nano),
	}
	hash, err := canonical.Hash(payload)
	if err != nil {
		return "dec_error"
	}
	return "dec_" + hash[len("sha256:"):18]
}

type FailingEvaluator struct{}

func (FailingEvaluator) Evaluate(invocation.Request, tools.Definition, risk.Result) (Decision, error) {
	return Decision{}, errors.New("policy evaluator unavailable")
}

func FailClosedDecision(err error) Decision {
	decision := Decision{
		Allow:       false,
		Decision:    invocation.DecisionDeny,
		ReasonCodes: []string{"POLICY_UNAVAILABLE_FAIL_CLOSED", fmt.Sprintf("POLICY_ERROR_%T", err)},
		PolicyVer:   LocalPolicyVersion,
		EvaluatedAt: time.Now().UTC(),
	}
	return withID(decision)
}
