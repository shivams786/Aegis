package approval

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/aegis/aegis/internal/authn"
	"github.com/aegis/aegis/internal/invocation"
)

type State string

const (
	StatePending   State = "PENDING"
	StateApproved  State = "APPROVED"
	StateRejected  State = "REJECTED"
	StateExpired   State = "EXPIRED"
	StateCancelled State = "CANCELLED"
)

var (
	ErrNotFound          = errors.New("approval request not found")
	ErrInvalidTransition = errors.New("invalid approval transition")
	ErrSelfApproval      = errors.New("requester cannot approve this request")
	ErrDuplicateDecision = errors.New("approver already decided")
)

type Request struct {
	ID                 string
	TenantID           string
	InvocationID       string
	RequesterSubjectID string
	RequesterAgentOwner string
	RequiredApprovals  int
	RequiredGroup      string
	RequesterMayApprove bool
	OwnerMayApprove     bool
	ReasonRequired      bool
	ExpiresAt           time.Time
	State               State
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
	Decisions           []Decision
}

type Decision struct {
	Approver authn.Subject
	Decision string
	Reason   string
	DecidedAt time.Time
}

type Store struct {
	mu       sync.Mutex
	requests map[string]Request
	now      func() time.Time
}

func NewStore() *Store {
	return &Store{
		requests: make(map[string]Request),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (s *Store) Create(tenantID, invocationID, requesterSubjectID, requesterAgentOwner string, requiredApprovals int, requiredGroup string, requesterMayApprove bool, ttl time.Duration) Request {
	if requiredApprovals <= 0 {
		requiredApprovals = 1
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	request := Request{
		ID:                  fmt.Sprintf("apr_%s", invocationID),
		TenantID:            tenantID,
		InvocationID:        invocationID,
		RequesterSubjectID:  requesterSubjectID,
		RequesterAgentOwner: requesterAgentOwner,
		RequiredApprovals:   requiredApprovals,
		RequiredGroup:       requiredGroup,
		RequesterMayApprove: requesterMayApprove,
		OwnerMayApprove:     false,
		ReasonRequired:      true,
		ExpiresAt:           now.Add(ttl),
		State:               StatePending,
		Version:             1,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	s.requests[key(tenantID, request.ID)] = request
	return request
}

func (s *Store) Get(tenantID, approvalID string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[key(tenantID, approvalID)]
	if !ok {
		return Request{}, ErrNotFound
	}
	if request.State == StatePending && !s.now().Before(request.ExpiresAt) {
		request.State = StateExpired
		request.Version++
		request.UpdatedAt = s.now()
		s.requests[key(tenantID, approvalID)] = request
	}
	return request, nil
}

func (s *Store) Approve(tenantID, approvalID string, approver authn.Subject, reason string) (Request, error) {
	return s.decide(tenantID, approvalID, approver, "APPROVE", reason)
}

func (s *Store) Reject(tenantID, approvalID string, approver authn.Subject, reason string) (Request, error) {
	return s.decide(tenantID, approvalID, approver, "REJECT", reason)
}

func (s *Store) decide(tenantID, approvalID string, approver authn.Subject, decision, reason string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	request, ok := s.requests[key(tenantID, approvalID)]
	if !ok {
		return Request{}, ErrNotFound
	}
	if request.State != StatePending {
		return Request{}, ErrInvalidTransition
	}
	if !now.Before(request.ExpiresAt) {
		request.State = StateExpired
		request.Version++
		request.UpdatedAt = now
		s.requests[key(tenantID, approvalID)] = request
		return Request{}, ErrInvalidTransition
	}
	if request.ReasonRequired && reason == "" {
		return Request{}, errors.New("approval reason is required")
	}
	if !request.RequesterMayApprove && approver.ID == request.RequesterSubjectID {
		return Request{}, ErrSelfApproval
	}
	if !request.OwnerMayApprove && approver.ID == request.RequesterAgentOwner {
		return Request{}, ErrSelfApproval
	}
	if request.RequiredGroup != "" && !slices.Contains(approver.Groups, request.RequiredGroup) {
		return Request{}, errors.New("approver is not in required group")
	}
	for _, existing := range request.Decisions {
		if existing.Approver.ID == approver.ID {
			return Request{}, ErrDuplicateDecision
		}
	}
	request.Decisions = append(request.Decisions, Decision{
		Approver: approver,
		Decision: decision,
		Reason:   reason,
		DecidedAt: now,
	})
	if decision == "REJECT" {
		request.State = StateRejected
	} else if countApprovals(request.Decisions) >= request.RequiredApprovals {
		request.State = StateApproved
	}
	request.Version++
	request.UpdatedAt = now
	s.requests[key(tenantID, approvalID)] = request
	return request, nil
}

func (s *Store) ListPending(tenantID string) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []Request{}
	for _, request := range s.requests {
		if request.TenantID == tenantID && request.State == StatePending {
			result = append(result, request)
		}
	}
	return result
}

func countApprovals(decisions []Decision) int {
	count := 0
	for _, decision := range decisions {
		if decision.Decision == "APPROVE" {
			count++
		}
	}
	return count
}

func key(tenantID, approvalID string) string {
	return tenantID + "\x00" + approvalID
}

func InvocationStateForApproval(state State) invocation.State {
	if state == StateApproved {
		return invocation.StateApproved
	}
	if state == StateRejected || state == StateExpired || state == StateCancelled {
		return invocation.StateDenied
	}
	return invocation.StatePendingApproval
}
