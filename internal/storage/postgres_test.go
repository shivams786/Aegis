package storage

import (
	"encoding/json"
	"testing"
)

func TestParseArgumentConstraintsSupportsSeedShape(t *testing.T) {
	constraints, err := parseArgumentConstraints(json.RawMessage(`{
		"currency": ["INR"],
		"max_amount_minor": 1000000,
		"required_fields": ["customer_id", "amount_minor"],
		"reject_unknown": true,
		"allowed_arg_names": ["customer_id", "amount_minor"]
	}`))
	if err != nil {
		t.Fatalf("parse constraints: %v", err)
	}
	if len(constraints.Currencies) != 1 || constraints.Currencies[0] != "INR" {
		t.Fatalf("unexpected currencies: %#v", constraints.Currencies)
	}
	if constraints.MaxAmountMinor == nil || *constraints.MaxAmountMinor != 1000000 {
		t.Fatalf("unexpected max amount: %#v", constraints.MaxAmountMinor)
	}
	if !constraints.RejectUnknown {
		t.Fatal("expected reject_unknown to be true")
	}
}
