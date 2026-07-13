package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aegis/aegis/internal/credentials"
	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/tools"
)

func TestPaymentsRefundIsIdempotent(t *testing.T) {
	provider := credentials.NewMemoryProvider()
	executor := NewDemoExecutor(provider)
	tool := tools.DemoDefinitions()[0]
	req := invocation.Request{
		TenantID: "tenant_acme", IdempotencyKey: "refund-1", Action: "refund",
		Resource: invocation.Resource{Type: "customer", ID: "CUST-1042"},
		Arguments: map[string]any{"amount_minor": int64(50000), "currency": "INR"},
	}
	credential, err := provider.Issue(credentials.Scope{TenantID: "tenant_acme", ToolID: "payments.refund", Action: "refund", Resource: "customer:CUST-1042", AmountMinor: 50000}, time.Minute)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	first, err := executor.Execute(context.Background(), req, tool, credential)
	if err != nil {
		t.Fatalf("first refund: %v", err)
	}
	second, err := executor.Execute(context.Background(), req, tool, credential)
	if err != nil {
		t.Fatalf("second refund: %v", err)
	}
	if first.Output["refund_id"] != second.Output["refund_id"] {
		t.Fatalf("expected same refund id, got %#v and %#v", first.Output, second.Output)
	}
}

func TestPaymentsUnknownOutcomeCanBeReconciled(t *testing.T) {
	provider := credentials.NewMemoryProvider()
	executor := NewDemoExecutor(provider)
	tool := tools.DemoDefinitions()[0]
	req := invocation.Request{
		TenantID: "tenant_acme", IdempotencyKey: "refund-unknown", Action: "refund",
		Resource: invocation.Resource{Type: "customer", ID: "CUST-1042"},
		Arguments: map[string]any{"amount_minor": int64(50000), "currency": "INR", "simulate": "unknown_outcome"},
	}
	credential, _ := provider.Issue(credentials.Scope{TenantID: "tenant_acme", ToolID: "payments.refund", Action: "refund", Resource: "customer:CUST-1042", AmountMinor: 50000}, time.Minute)
	_, err := executor.Execute(context.Background(), req, tool, credential)
	if !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("expected unknown outcome, got %v", err)
	}
	refund, ok := executor.payments.ReconcileByIdempotencyKey("tenant_acme", "refund-unknown")
	if !ok || refund["refund_id"] == "" {
		t.Fatalf("expected reconciled refund, got %#v ok=%t", refund, ok)
	}
}
