package invocation

import (
	"time"

	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/canonical"
)

type Protocol string

const (
	ProtocolREST Protocol = "rest"
	ProtocolMCP  Protocol = "mcp"
)

type State string

const (
	StateReceived               State = "RECEIVED"
	StateDenied                 State = "DENIED"
	StatePendingApproval        State = "PENDING_APPROVAL"
	StateApproved               State = "APPROVED"
	StateReserved               State = "RESERVED"
	StateExecuting              State = "EXECUTING"
	StateSucceeded              State = "SUCCEEDED"
	StateFailed                 State = "FAILED"
	StateCancelled              State = "CANCELLED"
	StateReconciliationRequired State = "RECONCILIATION_REQUIRED"
)

type Decision string

const (
	DecisionAllow           Decision = "ALLOW"
	DecisionDeny            Decision = "DENY"
	DecisionRequireApproval Decision = "REQUIRE_APPROVAL"
)

type ToolRef struct {
	ID            string `json:"id"`
	SchemaVersion int    `json:"schema_version"`
	SchemaHash    string `json:"schema_hash"`
}

type Resource struct {
	Type          string `json:"type"`
	ID            string `json:"id"`
	OwnerTenantID string `json:"owner_tenant_id"`
}

type RequestContext struct {
	SourceIP    string    `json:"source_ip,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
	TraceID     string    `json:"trace_id,omitempty"`
}

type Request struct {
	InvocationID      string         `json:"invocation_id"`
	TenantID          string         `json:"tenant_id"`
	Protocol          Protocol       `json:"protocol"`
	ProtocolRequestID string         `json:"protocol_request_id,omitempty"`
	IdempotencyKey    string         `json:"idempotency_key"`
	Subject           authn.Subject  `json:"subject"`
	Agent             authn.Agent    `json:"agent"`
	DelegationID      string         `json:"delegation_id"`
	Tool              ToolRef        `json:"tool"`
	Action            string         `json:"action"`
	Resource          Resource       `json:"resource"`
	Purpose           string         `json:"purpose"`
	Arguments         map[string]any `json:"arguments"`
	RequestContext    RequestContext `json:"request_context"`
}

type Response struct {
	ID                string         `json:"id"`
	State             State          `json:"state"`
	Decision          Decision       `json:"decision"`
	ReasonCodes       []string       `json:"reason_codes"`
	ApprovalRequestID string         `json:"approval_request_id,omitempty"`
	Result            map[string]any `json:"result,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	Links             map[string]any `json:"links,omitempty"`
}

func (r Request) CanonicalHash() (string, error) {
	canonicalForm := map[string]any{
		"tenant_id":       r.TenantID,
		"protocol":        r.Protocol,
		"idempotency_key": r.IdempotencyKey,
		"subject": map[string]any{
			"type":   r.Subject.Type,
			"id":     r.Subject.ID,
			"groups": r.Subject.Groups,
			"roles":  r.Subject.Roles,
		},
		"agent": map[string]any{
			"id":          r.Agent.ID,
			"trust_level": r.Agent.TrustLevel,
			"client_id":   r.Agent.ClientID,
		},
		"delegation_id": r.DelegationID,
		"tool": map[string]any{
			"id":             r.Tool.ID,
			"schema_version": r.Tool.SchemaVersion,
			"schema_hash":    r.Tool.SchemaHash,
		},
		"action":   r.Action,
		"resource": r.Resource,
		"purpose":  r.Purpose,
		"arguments": r.Arguments,
	}
	return canonical.Hash(canonicalForm)
}

func (r Request) AmountMinor() int64 {
	value, ok := r.Arguments["amount_minor"]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	default:
		return 0
	}
}
