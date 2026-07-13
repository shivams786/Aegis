package delegation

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

type Grant struct {
	ID                  string
	TenantID            string
	GrantorSubjectID    string
	GranteeAgentID      string
	AllowedTools        []string
	AllowedResources    []string
	ArgumentConstraints ArgumentConstraints
	Purpose             string
	Audience            string
	MaxDelegationDepth  int
	NotBefore           time.Time
	ExpiresAt           time.Time
	RevokedAt           *time.Time
}

type ArgumentConstraints struct {
	Currencies      []string
	MaxAmountMinor  *int64
	RequiredFields  []string
	RejectUnknown   bool
	AllowedArgNames []string
}

type Request struct {
	TenantID        string
	AgentID         string
	ToolID          string
	Resource        string
	Purpose         string
	Audience        string
	DelegationDepth int
	Arguments       map[string]any
	Now             time.Time
}

func ValidateGrant(grant Grant, request Request) error {
	now := request.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var errs []error
	if strings.TrimSpace(grant.ID) == "" {
		errs = append(errs, errors.New("delegation grant id is required"))
	}
	if grant.TenantID == "" || request.TenantID == "" || grant.TenantID != request.TenantID {
		errs = append(errs, errors.New("delegation tenant mismatch"))
	}
	if strings.TrimSpace(grant.GranteeAgentID) == "" || grant.GranteeAgentID != request.AgentID {
		errs = append(errs, errors.New("delegation grantee does not match agent"))
	}
	if !contains(grant.AllowedTools, request.ToolID) {
		errs = append(errs, errors.New("tool is outside delegated scope"))
	}
	if !contains(grant.AllowedResources, request.Resource) {
		errs = append(errs, errors.New("resource is outside delegated scope"))
	}
	if grant.Purpose == "" || grant.Purpose != request.Purpose {
		errs = append(errs, errors.New("purpose mismatch"))
	}
	if grant.Audience == "" || grant.Audience != request.Audience {
		errs = append(errs, errors.New("audience mismatch"))
	}
	if grant.MaxDelegationDepth < 0 || request.DelegationDepth > grant.MaxDelegationDepth {
		errs = append(errs, errors.New("delegation depth exceeds grant"))
	}
	if !grant.NotBefore.IsZero() && now.Before(grant.NotBefore) {
		errs = append(errs, errors.New("delegation grant is not active yet"))
	}
	if grant.ExpiresAt.IsZero() || !now.Before(grant.ExpiresAt) {
		errs = append(errs, errors.New("delegation grant is expired"))
	}
	if grant.RevokedAt != nil {
		errs = append(errs, errors.New("delegation grant is revoked"))
	}
	if err := validateArguments(grant.ArgumentConstraints, request.Arguments); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func validateArguments(constraints ArgumentConstraints, args map[string]any) error {
	var errs []error
	for _, field := range constraints.RequiredFields {
		if _, ok := args[field]; !ok {
			errs = append(errs, fmt.Errorf("required argument %q is missing", field))
		}
	}

	if constraints.RejectUnknown {
		for key := range args {
			if !contains(constraints.AllowedArgNames, key) {
				errs = append(errs, fmt.Errorf("unknown argument %q is not allowed", key))
			}
		}
	}

	if len(constraints.Currencies) > 0 {
		currency, ok := args["currency"].(string)
		if !ok || !contains(constraints.Currencies, currency) {
			errs = append(errs, errors.New("currency is outside delegated constraints"))
		}
	}

	if constraints.MaxAmountMinor != nil {
		amount, err := int64Arg(args["amount_minor"])
		if err != nil {
			errs = append(errs, fmt.Errorf("amount_minor is invalid: %w", err))
		} else if amount > *constraints.MaxAmountMinor {
			errs = append(errs, errors.New("amount_minor exceeds delegated maximum"))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func int64Arg(value any) (int64, error) {
	switch typed := value.(type) {
	case int:
		return int64(typed), nil
	case int32:
		return int64(typed), nil
	case int64:
		return typed, nil
	case float64:
		if math.Trunc(typed) != typed {
			return 0, errors.New("must be an integer minor-unit value")
		}
		return int64(typed), nil
	case json.Number:
		return typed.Int64()
	default:
		return 0, fmt.Errorf("unsupported type %T", value)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
