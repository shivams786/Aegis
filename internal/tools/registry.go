package tools

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aegis/aegis/internal/canonical"
)

type RiskClassification string
type SideEffectClassification string
type DataSensitivity string

const (
	RiskLow      RiskClassification = "LOW"
	RiskMedium   RiskClassification = "MEDIUM"
	RiskHigh     RiskClassification = "HIGH"
	RiskCritical RiskClassification = "CRITICAL"

	SideEffectReadOnly          SideEffectClassification = "READ_ONLY"
	SideEffectReversibleWrite   SideEffectClassification = "REVERSIBLE_WRITE"
	SideEffectIrreversibleWrite SideEffectClassification = "IRREVERSIBLE_WRITE"
	SideEffectFinancial         SideEffectClassification = "FINANCIAL"

	DataPublic       DataSensitivity = "PUBLIC"
	DataInternal     DataSensitivity = "INTERNAL"
	DataConfidential DataSensitivity = "CONFIDENTIAL"
	DataRestricted   DataSensitivity = "RESTRICTED"
)

type Definition struct {
	TenantID                   string                   `json:"tenant_id"`
	ID                         string                   `json:"tool_id"`
	DisplayName                string                   `json:"display_name"`
	MCPServerID                string                   `json:"mcp_server_id"`
	MCPToolName                string                   `json:"mcp_tool_name"`
	Description                string                   `json:"description"`
	InputSchema                map[string]any           `json:"input_schema"`
	OutputSchema               map[string]any           `json:"output_schema"`
	Risk                       RiskClassification       `json:"risk_classification"`
	SideEffect                 SideEffectClassification `json:"side_effect_classification"`
	DataSensitivity            DataSensitivity          `json:"data_sensitivity"`
	RequiredScopes             []string                 `json:"required_scopes"`
	RequiredCredentialTemplate string                   `json:"required_credential_template"`
	Timeout                    time.Duration            `json:"timeout"`
	RetryPolicy                RetryPolicy              `json:"retry_policy"`
	IdempotencySupported       bool                     `json:"idempotency_supported"`
	ApprovalDefaults           ApprovalDefaults         `json:"approval_defaults"`
	AllowedNetworkDestination  string                   `json:"allowed_network_destination"`
	Active                     bool                     `json:"active"`
	SchemaVersion              int                      `json:"schema_version"`
	SchemaHash                 string                   `json:"schema_hash"`
	ConnectorVersion           string                   `json:"connector_version"`
}

type RetryPolicy struct {
	MaxAttempts int           `json:"max_attempts"`
	Backoff     time.Duration `json:"backoff"`
}

type ApprovalDefaults struct {
	RequiredApprovals    int    `json:"required_approvals"`
	RequiredGroup        string `json:"required_group"`
	AmountThresholdMinor int64  `json:"amount_threshold_minor"`
}

type Registry struct {
	mu    sync.RWMutex
	tools map[string]map[string]Definition
}

func NewRegistry() *Registry {
	return &Registry{tools: make(map[string]map[string]Definition)}
}

func (r *Registry) Register(def Definition) (Definition, error) {
	if err := validateDefinition(def); err != nil {
		return Definition{}, err
	}
	hash, err := canonical.Hash(def.InputSchema)
	if err != nil {
		return Definition{}, fmt.Errorf("hash input schema: %w", err)
	}
	def.SchemaHash = hash
	if def.Timeout <= 0 {
		def.Timeout = 5 * time.Second
	}
	if def.RetryPolicy.MaxAttempts <= 0 {
		def.RetryPolicy.MaxAttempts = 1
	}
	if def.ConnectorVersion == "" {
		def.ConnectorVersion = "local-v1"
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tools[def.TenantID] == nil {
		r.tools[def.TenantID] = make(map[string]Definition)
	}
	existing, exists := r.tools[def.TenantID][def.ID]
	if exists && existing.SchemaVersion == def.SchemaVersion && existing.SchemaHash != def.SchemaHash {
		return Definition{}, errors.New("tool schema version cannot be reused with a different schema hash")
	}
	r.tools[def.TenantID][def.ID] = def
	return def, nil
}

func (r *Registry) Get(tenantID, toolID string) (Definition, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	byTenant := r.tools[tenantID]
	if byTenant == nil {
		return Definition{}, errors.New("tool not found")
	}
	def, ok := byTenant[toolID]
	if !ok || !def.Active {
		return Definition{}, errors.New("tool not found")
	}
	return def, nil
}

func (r *Registry) List(tenantID string, scopes []string) []Definition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	byTenant := r.tools[tenantID]
	result := make([]Definition, 0, len(byTenant))
	for _, def := range byTenant {
		if !def.Active {
			continue
		}
		if hasAllScopes(scopes, def.RequiredScopes) {
			result = append(result, def)
		}
	}
	return result
}

func validateDefinition(def Definition) error {
	var errs []error
	if strings.TrimSpace(def.TenantID) == "" {
		errs = append(errs, errors.New("tenant_id is required"))
	}
	if strings.TrimSpace(def.ID) == "" {
		errs = append(errs, errors.New("tool_id is required"))
	}
	if strings.Count(def.ID, ".") != 1 {
		errs = append(errs, errors.New("tool_id must be namespace-qualified as server.tool"))
	}
	if strings.TrimSpace(def.MCPServerID) == "" || strings.TrimSpace(def.MCPToolName) == "" {
		errs = append(errs, errors.New("mcp server and tool names are required"))
	}
	if def.SchemaVersion <= 0 {
		errs = append(errs, errors.New("schema_version must be positive"))
	}
	if len(def.InputSchema) == 0 || len(def.OutputSchema) == 0 {
		errs = append(errs, errors.New("input and output schemas are required"))
	}
	if def.Risk == "" || def.SideEffect == "" || def.DataSensitivity == "" {
		errs = append(errs, errors.New("tool classifications are required"))
	}
	if strings.TrimSpace(def.RequiredCredentialTemplate) == "" {
		errs = append(errs, errors.New("credential template is required"))
	}
	if strings.TrimSpace(def.AllowedNetworkDestination) == "" {
		errs = append(errs, errors.New("allowed network destination is required"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func hasAllScopes(actual, required []string) bool {
	set := make(map[string]struct{}, len(actual))
	for _, scope := range actual {
		set[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := set[scope]; !ok {
			return false
		}
	}
	return true
}

func SeedDemoRegistry() (*Registry, error) {
	registry := NewRegistry()
	for _, def := range DemoDefinitions() {
		if _, err := registry.Register(def); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func DemoDefinitions() []Definition {
	return []Definition{
		{
			TenantID: "tenant_acme", ID: "payments.refund", DisplayName: "Refund payment",
			MCPServerID: "payments-mcp", MCPToolName: "refund", Description: "Issue an idempotent refund.",
			InputSchema: objectSchema(false, map[string]any{
				"customer_id": map[string]any{"type": "string", "minLength": 1},
				"amount_minor": map[string]any{"type": "integer", "minimum": 1},
				"currency": map[string]any{"const": "INR"},
				"reason": map[string]any{"type": "string", "minLength": 3, "maxLength": 256},
				"simulate": map[string]any{"type": "string"},
			}, []string{"customer_id", "amount_minor", "currency", "reason"}),
			OutputSchema: objectSchema(true, map[string]any{
				"refund_id": map[string]any{"type": "string"},
				"status": map[string]any{"type": "string"},
			}, []string{"refund_id", "status"}),
			Risk: RiskHigh, SideEffect: SideEffectFinancial, DataSensitivity: DataConfidential,
			RequiredScopes: []string{"aegis.invoke", "payments:refund"}, RequiredCredentialTemplate: "payments-refund-scoped",
			Timeout: 5 * time.Second, RetryPolicy: RetryPolicy{MaxAttempts: 1}, IdempotencySupported: true,
			ApprovalDefaults: ApprovalDefaults{RequiredApprovals: 2, RequiredGroup: "finance", AmountThresholdMinor: 1_000_000},
			AllowedNetworkDestination: "local://payments-mcp", Active: true, SchemaVersion: 1,
		},
		{
			TenantID: "tenant_acme", ID: "payments.get_refund", DisplayName: "Get refund",
			MCPServerID: "payments-mcp", MCPToolName: "get_refund", Description: "Read refund status.",
			InputSchema: objectSchema(false, map[string]any{"refund_id": map[string]any{"type": "string"}}, []string{"refund_id"}),
			OutputSchema: objectSchema(false, map[string]any{"refund_id": map[string]any{"type": "string"}, "status": map[string]any{"type": "string"}}, []string{"refund_id", "status"}),
			Risk: RiskLow, SideEffect: SideEffectReadOnly, DataSensitivity: DataInternal,
			RequiredScopes: []string{"aegis.invoke", "payments:read"}, RequiredCredentialTemplate: "payments-read-scoped",
			AllowedNetworkDestination: "local://payments-mcp", Active: true, SchemaVersion: 1,
		},
		{
			TenantID: "tenant_acme", ID: "crm.get_customer", DisplayName: "Get customer",
			MCPServerID: "crm-mcp", MCPToolName: "get_customer",
			InputSchema: objectSchema(false, map[string]any{"customer_id": map[string]any{"type": "string"}}, []string{"customer_id"}),
			OutputSchema: objectSchema(true, map[string]any{"customer_id": map[string]any{"type": "string"}, "name": map[string]any{"type": "string"}}, []string{"customer_id", "name"}),
			Risk: RiskMedium, SideEffect: SideEffectReadOnly, DataSensitivity: DataConfidential,
			RequiredScopes: []string{"aegis.invoke", "crm:read"}, RequiredCredentialTemplate: "crm-read-scoped",
			AllowedNetworkDestination: "local://crm-mcp", Active: true, SchemaVersion: 1,
		},
		{
			TenantID: "tenant_acme", ID: "crm.export_customers", DisplayName: "Export customers",
			MCPServerID: "crm-mcp", MCPToolName: "export_customers",
			InputSchema: objectSchema(false, map[string]any{"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 10000}}, []string{"limit"}),
			OutputSchema: objectSchema(true, map[string]any{"count": map[string]any{"type": "integer"}}, []string{"count"}),
			Risk: RiskCritical, SideEffect: SideEffectReadOnly, DataSensitivity: DataRestricted,
			RequiredScopes: []string{"aegis.invoke", "crm:export"}, RequiredCredentialTemplate: "crm-export-scoped",
			ApprovalDefaults: ApprovalDefaults{RequiredApprovals: 1, RequiredGroup: "finance"}, AllowedNetworkDestination: "local://crm-mcp", Active: true, SchemaVersion: 1,
		},
		{
			TenantID: "tenant_acme", ID: "messaging.send_email", DisplayName: "Send email",
			MCPServerID: "messaging-mcp", MCPToolName: "send_email",
			InputSchema: objectSchema(false, map[string]any{
				"recipients": map[string]any{"type": "array", "minItems": 1},
				"subject": map[string]any{"type": "string", "minLength": 1, "maxLength": 200},
				"body": map[string]any{"type": "string", "minLength": 1, "maxLength": 10000},
			}, []string{"recipients", "subject", "body"}),
			OutputSchema: objectSchema(false, map[string]any{"message_id": map[string]any{"type": "string"}, "status": map[string]any{"type": "string"}}, []string{"message_id", "status"}),
			Risk: RiskMedium, SideEffect: SideEffectReversibleWrite, DataSensitivity: DataInternal,
			RequiredScopes: []string{"aegis.invoke", "messaging:send"}, RequiredCredentialTemplate: "messaging-send-scoped",
			ApprovalDefaults: ApprovalDefaults{RequiredApprovals: 1, RequiredGroup: "support"}, AllowedNetworkDestination: "local://messaging-mcp", Active: true, SchemaVersion: 1,
		},
	}
}

func objectSchema(additionalProperties bool, properties map[string]any, required []string) map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": additionalProperties,
		"required":             required,
		"properties":           properties,
	}
}
