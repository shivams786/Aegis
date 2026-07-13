package budget

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrInsufficientBudget = errors.New("insufficient budget")

type Account struct {
	TenantID       string
	ID             string
	ScopeType      string
	ScopeID        string
	Currency       string
	LimitMinor     int64
	ReservedMinor  int64
	CommittedMinor int64
	Version        int64
}

type Reservation struct {
	ID           string
	TenantID     string
	AccountID    string
	InvocationID string
	AmountMinor  int64
	Currency     string
	CreatedAt    time.Time
	Committed    bool
	Released     bool
}

type Ledger struct {
	mu           sync.Mutex
	accounts     map[string]Account
	reservations map[string]Reservation
	now          func() time.Time
}

func NewLedger() *Ledger {
	return &Ledger{
		accounts:     make(map[string]Account),
		reservations: make(map[string]Reservation),
		now:          func() time.Time { return time.Now().UTC() },
	}
}

func (l *Ledger) UpsertAccount(account Account) error {
	if account.TenantID == "" || account.ID == "" || account.Currency == "" {
		return errors.New("budget account tenant, id, and currency are required")
	}
	if account.LimitMinor < 0 || account.ReservedMinor < 0 || account.CommittedMinor < 0 {
		return errors.New("budget amounts must not be negative")
	}
	if account.ReservedMinor+account.CommittedMinor > account.LimitMinor {
		return ErrInsufficientBudget
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if account.Version <= 0 {
		account.Version = 1
	}
	l.accounts[key(account.TenantID, account.ID)] = account
	return nil
}

func (l *Ledger) Reserve(tenantID, accountID, invocationID, currency string, amountMinor int64) (Reservation, error) {
	if amountMinor < 0 {
		return Reservation{}, errors.New("reservation amount must not be negative")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	accountKey := key(tenantID, accountID)
	account, ok := l.accounts[accountKey]
	if !ok {
		return Reservation{}, errors.New("budget account not found")
	}
	if account.Currency != currency {
		return Reservation{}, errors.New("budget currency mismatch")
	}
	if account.ReservedMinor+account.CommittedMinor+amountMinor > account.LimitMinor {
		return Reservation{}, ErrInsufficientBudget
	}
	account.ReservedMinor += amountMinor
	account.Version++
	l.accounts[accountKey] = account
	reservation := Reservation{
		ID:           fmt.Sprintf("bgr_%s_%d", invocationID, account.Version),
		TenantID:     tenantID,
		AccountID:    accountID,
		InvocationID: invocationID,
		AmountMinor:  amountMinor,
		Currency:     currency,
		CreatedAt:    l.now(),
	}
	l.reservations[reservation.ID] = reservation
	return reservation, nil
}

func (l *Ledger) Commit(reservationID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	reservation, account, err := l.loadReservation(reservationID)
	if err != nil {
		return err
	}
	if reservation.Committed {
		return nil
	}
	if reservation.Released {
		return errors.New("cannot commit released reservation")
	}
	account.ReservedMinor -= reservation.AmountMinor
	account.CommittedMinor += reservation.AmountMinor
	account.Version++
	reservation.Committed = true
	l.accounts[key(account.TenantID, account.ID)] = account
	l.reservations[reservationID] = reservation
	return nil
}

func (l *Ledger) Release(reservationID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	reservation, account, err := l.loadReservation(reservationID)
	if err != nil {
		return err
	}
	if reservation.Released || reservation.Committed {
		return nil
	}
	account.ReservedMinor -= reservation.AmountMinor
	account.Version++
	reservation.Released = true
	l.accounts[key(account.TenantID, account.ID)] = account
	l.reservations[reservationID] = reservation
	return nil
}

func (l *Ledger) Account(tenantID, accountID string) (Account, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	account, ok := l.accounts[key(tenantID, accountID)]
	return account, ok
}

func (l *Ledger) loadReservation(reservationID string) (Reservation, Account, error) {
	reservation, ok := l.reservations[reservationID]
	if !ok {
		return Reservation{}, Account{}, errors.New("budget reservation not found")
	}
	account, ok := l.accounts[key(reservation.TenantID, reservation.AccountID)]
	if !ok {
		return Reservation{}, Account{}, errors.New("budget account not found")
	}
	return reservation, account, nil
}

func key(tenantID, id string) string {
	return tenantID + "\x00" + id
}
