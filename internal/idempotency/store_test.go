package idempotency

import "testing"

func TestStoreRejectsPoisonedReplay(t *testing.T) {
	store := NewStore()
	if _, replay, err := store.Begin("tenant", "tool", "action", "key", "hash-a"); err != nil || replay {
		t.Fatalf("unexpected first begin result replay=%t err=%v", replay, err)
	}
	if _, _, err := store.Begin("tenant", "tool", "action", "key", "hash-b"); err != ErrConflict {
		t.Fatalf("expected conflict, got %v", err)
	}
}
