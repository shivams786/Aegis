package canonical

import "testing"

func TestHashJSONStableForEquivalentObjects(t *testing.T) {
	left, err := HashJSON([]byte(`{"b":2,"a":{"d":4,"c":3}}`))
	if err != nil {
		t.Fatalf("hash left: %v", err)
	}
	right, err := HashJSON([]byte(`{"a":{"c":3,"d":4},"b":2}`))
	if err != nil {
		t.Fatalf("hash right: %v", err)
	}
	if left != right {
		t.Fatalf("expected stable hash, got %s and %s", left, right)
	}
}
