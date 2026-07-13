package tenancy

import (
	"context"
	"testing"
)

func TestTenantIDRequiresContextValue(t *testing.T) {
	if _, err := TenantID(context.Background()); err == nil {
		t.Fatal("expected missing tenant context to fail")
	}
}

func TestTenantIDReturnsContextValue(t *testing.T) {
	ctx := ContextWithTenant(context.Background(), "tenant_acme")

	tenantID, err := TenantID(ctx)
	if err != nil {
		t.Fatalf("expected tenant context: %v", err)
	}
	if tenantID != "tenant_acme" {
		t.Fatalf("unexpected tenant id: %s", tenantID)
	}
}
