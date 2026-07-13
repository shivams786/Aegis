package tools

import "testing"

func TestRegistryRejectsUnqualifiedToolID(t *testing.T) {
	registry := NewRegistry()
	def := DemoDefinitions()[0]
	def.ID = "refund"

	if _, err := registry.Register(def); err == nil {
		t.Fatal("expected unqualified tool id to be rejected")
	}
}

func TestValidateInputRejectsUnknownSensitiveField(t *testing.T) {
	def := DemoDefinitions()[0]
	registry := NewRegistry()
	registered, err := registry.Register(def)
	if err != nil {
		t.Fatalf("register tool: %v", err)
	}

	err = ValidateInput(registered, map[string]any{
		"customer_id": "CUST-1042",
		"amount_minor": int64(50000),
		"currency": "INR",
		"reason": "duplicate_charge",
		"extra": "not allowed",
	})
	if err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
}
