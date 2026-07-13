package approval

import (
	"errors"
	"testing"
	"time"

	"github.com/aegis/aegis/internal/authn"
)

func TestApprovalBlocksSelfApproval(t *testing.T) {
	store := NewStore()
	request := store.Create("tenant_acme", "inv_1", "user_123", "user_123", 1, "finance", false, time.Hour)

	_, err := store.Approve("tenant_acme", request.ID, authn.Subject{ID: "user_123", Groups: []string{"finance"}}, "looks good")
	if !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("expected self approval rejection, got %v", err)
	}
}

func TestApprovalRequiresDistinctApprovers(t *testing.T) {
	store := NewStore()
	request := store.Create("tenant_acme", "inv_1", "user_123", "user_123", 2, "finance", false, time.Hour)
	approver := authn.Subject{ID: "approver_1", Groups: []string{"finance"}}

	if _, err := store.Approve("tenant_acme", request.ID, approver, "first"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	_, err := store.Approve("tenant_acme", request.ID, approver, "again")
	if !errors.Is(err, ErrDuplicateDecision) {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
}

func TestApprovalCompletesAfterRequiredCount(t *testing.T) {
	store := NewStore()
	request := store.Create("tenant_acme", "inv_1", "user_123", "user_123", 2, "finance", false, time.Hour)

	updated, err := store.Approve("tenant_acme", request.ID, authn.Subject{ID: "approver_1", Groups: []string{"finance"}}, "first")
	if err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if updated.State != StatePending {
		t.Fatalf("expected pending after first approval, got %s", updated.State)
	}
	updated, err = store.Approve("tenant_acme", request.ID, authn.Subject{ID: "approver_2", Groups: []string{"finance"}}, "second")
	if err != nil {
		t.Fatalf("second approve: %v", err)
	}
	if updated.State != StateApproved {
		t.Fatalf("expected approved, got %s", updated.State)
	}
}
