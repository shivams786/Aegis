package execution

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aegis/aegis/internal/credentials"
	"github.com/aegis/aegis/internal/invocation"
	"github.com/aegis/aegis/internal/tools"
)

var ErrUnknownOutcome = errors.New("downstream outcome is unknown")

type Outcome string

const (
	OutcomeSucceeded Outcome = "SUCCEEDED"
	OutcomeFailed    Outcome = "FAILED"
	OutcomeUnknown   Outcome = "UNKNOWN"
)

type Result struct {
	Outcome Outcome        `json:"outcome"`
	Output  map[string]any `json:"output,omitempty"`
	Error   string         `json:"error,omitempty"`
}

type Executor interface {
	Execute(ctx context.Context, req invocation.Request, tool tools.Definition, credential credentials.Credential) (Result, error)
}

type DemoExecutor struct {
	credentialProvider credentials.Provider
	payments           *PaymentsServer
	crm                *CRMServer
	messaging          *MessagingServer
}

func NewDemoExecutor(provider credentials.Provider) *DemoExecutor {
	return &DemoExecutor{
		credentialProvider: provider,
		payments:           NewPaymentsServer(provider),
		crm:                NewCRMServer(provider),
		messaging:          NewMessagingServer(provider),
	}
}

func (e *DemoExecutor) Execute(ctx context.Context, req invocation.Request, tool tools.Definition, credential credentials.Credential) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, tool.Timeout)
	defer cancel()
	switch tool.ID {
	case "payments.refund":
		return e.payments.Refund(ctx, req, tool, credential)
	case "payments.get_refund":
		return e.payments.GetRefund(ctx, req, tool, credential)
	case "crm.get_customer", "crm.search_customers", "crm.export_customers":
		return e.crm.Execute(ctx, req, tool, credential)
	case "messaging.send_email":
		return e.messaging.SendEmail(ctx, req, tool, credential)
	default:
		return Result{Outcome: OutcomeFailed, Error: "unknown tool"}, errors.New("unknown tool")
	}
}

func (e *DemoExecutor) ReconcilePaymentByIdempotencyKey(tenantID, key string) (map[string]any, bool) {
	return e.payments.ReconcileByIdempotencyKey(tenantID, key)
}

type PaymentsServer struct {
	mu          sync.Mutex
	credential credentials.Provider
	refunds     map[string]map[string]any
	byKey       map[string]string
}

func NewPaymentsServer(provider credentials.Provider) *PaymentsServer {
	return &PaymentsServer{
		credential: provider,
		refunds:    make(map[string]map[string]any),
		byKey:      make(map[string]string),
	}
}

func (s *PaymentsServer) Refund(ctx context.Context, req invocation.Request, tool tools.Definition, credential credentials.Credential) (Result, error) {
	required := credentials.Scope{TenantID: req.TenantID, ToolID: tool.ID, Action: req.Action, Resource: req.Resource.Type + ":" + req.Resource.ID, AmountMinor: req.AmountMinor()}
	if err := s.credential.Validate(credential.Token, required); err != nil {
		return Result{Outcome: OutcomeFailed, Error: "credential rejected"}, err
	}
	if simulate, _ := req.Arguments["simulate"].(string); simulate == "timeout" {
		<-ctx.Done()
		return Result{Outcome: OutcomeUnknown, Error: "timeout"}, ErrUnknownOutcome
	} else if simulate == "unknown_outcome" {
		s.mu.Lock()
		refundID := s.ensureRefundLocked(req)
		s.mu.Unlock()
		return Result{Outcome: OutcomeUnknown, Output: map[string]any{"refund_id": refundID, "status": "unknown"}}, ErrUnknownOutcome
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	refundID := s.ensureRefundLocked(req)
	return Result{Outcome: OutcomeSucceeded, Output: s.refunds[refundID]}, nil
}

func (s *PaymentsServer) GetRefund(ctx context.Context, req invocation.Request, tool tools.Definition, credential credentials.Credential) (Result, error) {
	refundID, _ := req.Arguments["refund_id"].(string)
	required := credentials.Scope{TenantID: req.TenantID, ToolID: tool.ID, Action: req.Action, Resource: "refund:" + refundID}
	if err := s.credential.Validate(credential.Token, required); err != nil {
		return Result{Outcome: OutcomeFailed, Error: "credential rejected"}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	refund, ok := s.refunds[refundID]
	if !ok {
		return Result{Outcome: OutcomeFailed, Error: "refund not found"}, errors.New("refund not found")
	}
	return Result{Outcome: OutcomeSucceeded, Output: refund}, nil
}

func (s *PaymentsServer) ReconcileByIdempotencyKey(tenantID, key string) (map[string]any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refundID, ok := s.byKey[tenantID+"\x00"+key]
	if !ok {
		return nil, false
	}
	return s.refunds[refundID], true
}

func (s *PaymentsServer) ensureRefundLocked(req invocation.Request) string {
	idempotencyKey := req.TenantID + "\x00" + req.IdempotencyKey
	if existing, ok := s.byKey[idempotencyKey]; ok {
		return existing
	}
	refundID := fmt.Sprintf("rfnd_%s_%d", req.Resource.ID, len(s.refunds)+1)
	refund := map[string]any{
		"refund_id": refundID,
		"status": "succeeded",
		"customer_id": req.Resource.ID,
		"amount_minor": req.AmountMinor(),
		"currency": req.Arguments["currency"],
	}
	s.refunds[refundID] = refund
	s.byKey[idempotencyKey] = refundID
	return refundID
}

type CRMServer struct {
	credential credentials.Provider
	customers  map[string]map[string]any
}

func NewCRMServer(provider credentials.Provider) *CRMServer {
	return &CRMServer{
		credential: provider,
		customers: map[string]map[string]any{
			"tenant_acme:CUST-1042": {"customer_id": "CUST-1042", "name": "Ada Customer", "tenant_id": "tenant_acme", "restricted_note": "redacted"},
			"tenant_globex:CUST-9001": {"customer_id": "CUST-9001", "name": "Globex Customer", "tenant_id": "tenant_globex", "restricted_note": "redacted"},
		},
	}
}

func (s *CRMServer) Execute(ctx context.Context, req invocation.Request, tool tools.Definition, credential credentials.Credential) (Result, error) {
	required := credentials.Scope{TenantID: req.TenantID, ToolID: tool.ID, Action: req.Action, Resource: req.Resource.Type + ":" + req.Resource.ID}
	if err := s.credential.Validate(credential.Token, required); err != nil {
		return Result{Outcome: OutcomeFailed, Error: "credential rejected"}, err
	}
	switch tool.ID {
	case "crm.get_customer":
		customerID, _ := req.Arguments["customer_id"].(string)
		customer, ok := s.customers[req.TenantID+":"+customerID]
		if !ok {
			return Result{Outcome: OutcomeFailed, Error: "not found"}, errors.New("customer not found")
		}
		output := map[string]any{"customer_id": customer["customer_id"], "name": customer["name"]}
		return Result{Outcome: OutcomeSucceeded, Output: output}, nil
	case "crm.export_customers":
		return Result{Outcome: OutcomeSucceeded, Output: map[string]any{"count": len(s.customers)}}, nil
	default:
		return Result{Outcome: OutcomeFailed, Error: "unsupported crm tool"}, errors.New("unsupported crm tool")
	}
}

type MessagingServer struct {
	credential credentials.Provider
	allowedDomains []string
	mu       sync.Mutex
	sent     []map[string]any
}

func NewMessagingServer(provider credentials.Provider) *MessagingServer {
	return &MessagingServer{credential: provider, allowedDomains: []string{"example.com", "acme.example"}}
}

func (s *MessagingServer) SendEmail(ctx context.Context, req invocation.Request, tool tools.Definition, credential credentials.Credential) (Result, error) {
	required := credentials.Scope{TenantID: req.TenantID, ToolID: tool.ID, Action: req.Action, Resource: req.Resource.Type + ":" + req.Resource.ID}
	if err := s.credential.Validate(credential.Token, required); err != nil {
		return Result{Outcome: OutcomeFailed, Error: "credential rejected"}, err
	}
	recipients, _ := req.Arguments["recipients"].([]any)
	for _, recipient := range recipients {
		email, ok := recipient.(string)
		if !ok || !s.allowedDomain(email) {
			return Result{Outcome: OutcomeFailed, Error: "recipient domain is not allowed"}, errors.New("recipient domain is not allowed")
		}
	}
	message := map[string]any{"message_id": fmt.Sprintf("msg_%d", len(s.sent)+1), "status": "sent"}
	s.mu.Lock()
	s.sent = append(s.sent, message)
	s.mu.Unlock()
	return Result{Outcome: OutcomeSucceeded, Output: message}, nil
}

func (s *MessagingServer) allowedDomain(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	for _, domain := range s.allowedDomains {
		if parts[1] == domain {
			return true
		}
	}
	return false
}
