package budget

import (
	"errors"
	"sync"
	"testing"
)

func TestLedgerPreventsConcurrentOverspend(t *testing.T) {
	ledger := NewLedger()
	if err := ledger.UpsertAccount(Account{TenantID: "tenant_acme", ID: "budget", Currency: "INR", LimitMinor: 100}); err != nil {
		t.Fatalf("upsert account: %v", err)
	}

	var wg sync.WaitGroup
	successes := 0
	var mu sync.Mutex
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reservation, err := ledger.Reserve("tenant_acme", "budget", "inv", "INR", 10)
			if err == nil {
				_ = ledger.Commit(reservation.ID)
				mu.Lock()
				successes++
				mu.Unlock()
			} else if !errors.Is(err, ErrInsufficientBudget) {
				t.Errorf("unexpected reserve error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	account, _ := ledger.Account("tenant_acme", "budget")
	if account.CommittedMinor+account.ReservedMinor > account.LimitMinor {
		t.Fatalf("overspent budget: %#v", account)
	}
	if successes != 10 {
		t.Fatalf("expected 10 successful reservations, got %d", successes)
	}
}
