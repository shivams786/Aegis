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

func TestRootManifestCoversEventRange(t *testing.T) {
	chain := NewChain()
	_, _ = chain.Append("tenant_acme", "inv_1", "INVOCATION_RECEIVED", "agent", "agent_1", "OK", map[string]any{})
	_, _ = chain.Append("tenant_acme", "inv_1", "INVOCATION_SUCCEEDED", "agent", "agent_1", "OK", map[string]any{})

	root, err := RootManifest("tenant_acme", chain.Events("tenant_acme"), "dev-signer", chain.now())
	if err != nil {
		t.Fatalf("root manifest: %v", err)
	}
	if root.FromSequenceNo != 1 || root.ToSequenceNo != 2 || root.RootHash == "" || root.Signature == "" {
		t.Fatalf("unexpected root manifest: %#v", root)
	}
}
