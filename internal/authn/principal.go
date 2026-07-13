package authn

import (
	"errors"
	"strings"
	"time"
)

type PrincipalType string

const (
	PrincipalHuman        PrincipalType = "human"
	PrincipalAgent        PrincipalType = "agent"
	PrincipalService      PrincipalType = "service_account"
	PrincipalApprover     PrincipalType = "approver"
	PrincipalAdmin        PrincipalType = "administrator"
	PrincipalMCPClient    PrincipalType = "mcp_client"
	PrincipalToolWorkload PrincipalType = "downstream_tool_workload"
)

type Subject struct {
	Type   PrincipalType `json:"type"`
	ID     string        `json:"id"`
	Groups []string      `json:"groups,omitempty"`
	Roles  []string      `json:"roles,omitempty"`
}

type Agent struct {
	ID         string `json:"id"`
	TrustLevel int    `json:"trust_level"`
	OwnerID    string `json:"owner_id,omitempty"`
	ClientID   string `json:"client_id"`
}

type DelegationContext struct {
	ID        string    `json:"id"`
	Depth     int       `json:"depth"`
	Purpose   string    `json:"purpose"`
	Audience  string    `json:"audience"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ActingIdentity struct {
	TenantID   string            `json:"tenant_id"`
	Subject    Subject           `json:"subject"`
	Agent      Agent             `json:"agent"`
	Delegation DelegationContext `json:"delegation"`
	ClientID   string            `json:"client_id"`
	TokenType  string            `json:"token_type"`
	Scopes     []string          `json:"scopes"`
}

func (i ActingIdentity) Validate() error {
	var errs []error
	if strings.TrimSpace(i.TenantID) == "" {
		errs = append(errs, errors.New("tenant_id is required"))
	}
	if strings.TrimSpace(i.Subject.ID) == "" {
		errs = append(errs, errors.New("subject.id is required"))
	}
	if strings.TrimSpace(string(i.Subject.Type)) == "" {
		errs = append(errs, errors.New("subject.type is required"))
	} else if !isAllowedPrincipalType(i.Subject.Type) {
		errs = append(errs, errors.New("subject.type is not supported"))
	}
	if strings.TrimSpace(i.Agent.ID) == "" {
		errs = append(errs, errors.New("agent.id is required"))
	}
	if strings.TrimSpace(i.Agent.ClientID) == "" {
		errs = append(errs, errors.New("agent.client_id is required"))
	}
	if strings.TrimSpace(i.Delegation.ID) == "" {
		errs = append(errs, errors.New("delegation.id is required"))
	}
	if i.Delegation.Depth < 0 {
		errs = append(errs, errors.New("delegation.depth must not be negative"))
	}
	if i.Delegation.ExpiresAt.IsZero() {
		errs = append(errs, errors.New("delegation.expires_at is required"))
	}
	if strings.TrimSpace(i.ClientID) == "" {
		errs = append(errs, errors.New("client_id is required"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func isAllowedPrincipalType(value PrincipalType) bool {
	switch value {
	case PrincipalHuman,
		PrincipalAgent,
		PrincipalService,
		PrincipalApprover,
		PrincipalAdmin,
		PrincipalMCPClient,
		PrincipalToolWorkload:
		return true
	default:
		return false
	}
}
