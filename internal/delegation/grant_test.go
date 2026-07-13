package delegation

import (
	"strings"
	"testing"
	"time"
)

func TestValidateGrantAllowsWithinConstraints(t *testing.T) {
	grant := validGrant(t)
	request := validRequest()

	if err := ValidateGrant(grant, request); err != nil {
		t.Fatalf("expected delegation to validate: %v", err)
	}
}

func TestValidateGrantRejectsEscalatedAmount(t *testing.T) {
	grant := validGrant(t)
	request := validRequest()
	request.Arguments["amount_minor"] = int64(50_000_00)

	err := ValidateGrant(grant, request)
	if err == nil || !strings.Contains(err.Error(), "amount_minor exceeds delegated maximum") {
		t.Fatalf("expected delegated amount escalation to fail, got %v", err)
	}
}

func TestValidateGrantRejectsCrossTenant(t *testing.T) {
	grant := validGrant(t)
	request := validRequest()
	request.TenantID = "tenant_globex"

	err := ValidateGrant(grant, request)
	if err == nil || !strings.Contains(err.Error(), "tenant mismatch") {
		t.Fatalf("expected cross-tenant request to fail, got %v", err)
	}
}

func TestValidateGrantRejectsDelegationDepthIncrease(t *testing.T) {
	grant := validGrant(t)
	request := validRequest()
	request.DelegationDepth = 2

	err := ValidateGrant(grant, request)
	if err == nil || !strings.Contains(err.Error(), "delegation depth exceeds grant") {
		t.Fatalf("expected delegation depth escalation to fail, got %v", err)
	}
}

func TestValidateGrantRejectsUnknownArgumentsForStrictGrant(t *testing.T) {
	grant := validGrant(t)
	request := validRequest()
	request.Arguments["unapproved_field"] = "please allow me"

	err := ValidateGrant(grant, request)
	if err == nil || !strings.Contains(err.Error(), "unknown argument") {
		t.Fatalf("expected unknown argument to fail, got %v", err)
	}
}

func validGrant(t *testing.T) Grant {
	t.Helper()
	maxAmount := int64(10_000_00)
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	return Grant{
		ID:                 "dlg_789",
		TenantID:           "tenant_acme",
		GrantorSubjectID:   "user_123",
		GranteeAgentID:     "agent_refund_assistant",
		AllowedTools:       []string{"payments.refund"},
		AllowedResources:   []string{"customer:CUST-1042"},
		Purpose:            "customer_support",
		Audience:           "aegis",
		MaxDelegationDepth: 1,
		NotBefore:          now.Add(-time.Hour),
		ExpiresAt:          now.Add(time.Hour),
		ArgumentConstraints: ArgumentConstraints{
			Currencies:      []string{"INR"},
			MaxAmountMinor:  &maxAmount,
			RequiredFields:  []string{"customer_id", "amount_minor", "currency", "reason"},
			RejectUnknown:   true,
			AllowedArgNames: []string{"customer_id", "amount_minor", "currency", "reason"},
		},
	}
}

func validRequest() Request {
	return Request{
		TenantID:        "tenant_acme",
		AgentID:         "agent_refund_assistant",
		ToolID:          "payments.refund",
		Resource:        "customer:CUST-1042",
		Purpose:         "customer_support",
		Audience:        "aegis",
		DelegationDepth: 1,
		Now:             time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
		Arguments: map[string]any{
			"customer_id":  "CUST-1042",
			"amount_minor": int64(500_00),
			"currency":     "INR",
			"reason":       "duplicate_charge",
		},
	}
}
