package audit

import "testing"

func TestVerifyDetectsTampering(t *testing.T) {
	chain := NewChain()
	if _, err := chain.Append("tenant_acme", "inv_1", "INVOCATION_RECEIVED", "agent", "agent_1", "OK", map[string]any{"x": "y"}); err != nil {
		t.Fatalf("append first: %v", err)
	}
	if _, err := chain.Append("tenant_acme", "inv_1", "INVOCATION_SUCCEEDED", "agent", "agent_1", "OK", map[string]any{"status": "ok"}); err != nil {
		t.Fatalf("append second: %v", err)
	}
	events := chain.Events("tenant_acme")
	if err := Verify(events); err != nil {
		t.Fatalf("expected untouched chain to verify: %v", err)
	}
	events[0].RedactedPayload["x"] = "tampered"
	if err := Verify(events); err == nil {
		t.Fatal("expected tampered chain to fail verification")
	}
}
