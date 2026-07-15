package idempotency

import (
	"errors"
	"sync"

	"github.com/aegis/aegis/internal/invocation"
)

var ErrConflict = errors.New("idempotency key reused with different canonical request hash")

type Record struct {
	TenantID             string
	ToolID               string
	Action               string
	Key                  string
	CanonicalRequestHash string
	Response             invocation.Response
	Completed            bool
}

type Store struct {
	mu      sync.Mutex
	records map[string]Record
}

func NewStore() *Store {
	return &Store{records: make(map[string]Record)}
}

func (s *Store) Begin(tenantID, toolID, action, key, hash string) (Record, bool, error) {
	if key == "" {
		return Record{}, false, errors.New("idempotency key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recordKey := compoundKey(tenantID, toolID, action, key)
	existing, ok := s.records[recordKey]
	if ok {
		if existing.CanonicalRequestHash != hash {
			return Record{}, false, ErrConflict
		}
		return existing, true, nil
	}
	record := Record{TenantID: tenantID, ToolID: toolID, Action: action, Key: key, CanonicalRequestHash: hash}
	s.records[recordKey] = record
	return record, false, nil
}

func (s *Store) Complete(record Record, response invocation.Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record.Response = response
	record.Completed = true
	s.records[compoundKey(record.TenantID, record.ToolID, record.Action, record.Key)] = record
}

func (s *Store) CompleteKey(tenantID, toolID, action, key string, response invocation.Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recordKey := compoundKey(tenantID, toolID, action, key)
	record := s.records[recordKey]
	record.TenantID = tenantID
	record.ToolID = toolID
	record.Action = action
	record.Key = key
	record.Response = response
	record.Completed = true
	s.records[recordKey] = record
}

func compoundKey(tenantID, toolID, action, key string) string {
	return tenantID + "\x00" + toolID + "\x00" + action + "\x00" + key
}
