package credentials

import (
	"testing"
	"time"
)

func TestMemoryProviderRejectsScopeReuse(t *testing.T) {
	provider := NewMemoryProvider()
	credential, err := provider.Issue(Scope{TenantID: "tenant_acme", ToolID: "payments.refund", Action: "refund", Resource: "customer:CUST-1042", AmountMinor: 50000}, time.Minute)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	err = provider.Validate(credential.Token, Scope{TenantID: "tenant_acme", ToolID: "payments.refund", Action: "refund", Resource: "customer:CUST-9999", AmountMinor: 50000})
	if err == nil {
		t.Fatal("expected credential reuse for another resource to fail")
	}
}
