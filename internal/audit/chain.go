package audit

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aegis/aegis/internal/canonical"
)

type Event struct {
	TenantID       string         `json:"tenant_id"`
	SequenceNo    int64          `json:"sequence_no"`
	EventID        string         `json:"event_id"`
	InvocationID  string         `json:"invocation_id,omitempty"`
	EventType     string         `json:"event_type"`
	ActorType     string         `json:"actor_type"`
	ActorID       string         `json:"actor_id"`
	SafeReasonCode string         `json:"safe_reason_code,omitempty"`
	RedactedPayload map[string]any `json:"redacted_payload"`
	PreviousHash  string         `json:"previous_hash,omitempty"`
	EventHash     string         `json:"event_hash"`
	OccurredAt    time.Time      `json:"occurred_at"`
}

type Chain struct {
	mu     sync.Mutex
	events map[string][]Event
	now    func() time.Time
}

type Root struct {
	TenantID       string    `json:"tenant_id"`
	RootID         string    `json:"root_id"`
	FromSequenceNo int64     `json:"from_sequence_no"`
	ToSequenceNo   int64     `json:"to_sequence_no"`
	RootHash       string    `json:"root_hash"`
	GeneratedAt    time.Time `json:"generated_at"`
	Signature      string    `json:"signature"`
}

func NewChain() *Chain {
	return &Chain{events: make(map[string][]Event), now: func() time.Time { return time.Now().UTC() }}
}

func (c *Chain) Append(tenantID, invocationID, eventType, actorType, actorID, reason string, payload map[string]any) (Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := c.events[tenantID]
	sequence := int64(len(events) + 1)
	previousHash := ""
	if len(events) > 0 {
		previousHash = events[len(events)-1].EventHash
	}
	event := Event{
		TenantID: tenantID, SequenceNo: sequence, EventID: fmt.Sprintf("aud_%s_%d", tenantID, sequence),
		InvocationID: invocationID, EventType: eventType, ActorType: actorType, ActorID: actorID,
		SafeReasonCode: reason, RedactedPayload: payload, PreviousHash: previousHash, OccurredAt: c.now(),
	}
	hash, err := eventHash(event)
	if err != nil {
		return Event{}, err
	}
	event.EventHash = hash
	c.events[tenantID] = append(events, event)
	return event, nil
}

func (c *Chain) Events(tenantID string) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := c.events[tenantID]
	result := make([]Event, len(events))
	copy(result, events)
	return result
}

func Verify(events []Event) error {
	return VerifySegment(events, "", 1)
}

func VerifySegment(events []Event, previousHash string, expectedStartSequence int64) error {
	if expectedStartSequence <= 0 {
		return errors.New("expected start sequence must be positive")
	}
	for i, event := range events {
		expectedSequence := expectedStartSequence + int64(i)
		if event.SequenceNo != expectedSequence {
			return fmt.Errorf("audit sequence broken at index %d", i)
		}
		if event.PreviousHash != previousHash {
			return fmt.Errorf("audit previous hash mismatch at sequence %d", event.SequenceNo)
		}
		expected, err := eventHash(event)
		if err != nil {
			return err
		}
		if event.EventHash != expected {
			return fmt.Errorf("audit event hash mismatch at sequence %d", event.SequenceNo)
		}
		previousHash = event.EventHash
	}
	return nil
}

func RootManifest(tenantID string, events []Event, signer string, generatedAt time.Time) (Root, error) {
	if len(events) == 0 {
		return Root{}, errors.New("cannot generate audit root for empty event set")
	}
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	leafHashes := make([]any, 0, len(events))
	for _, event := range events {
		leafHashes = append(leafHashes, event.EventHash)
	}
	rootHash, err := canonical.Hash(map[string]any{
		"tenant_id": tenantID,
		"from": events[0].SequenceNo,
		"to": events[len(events)-1].SequenceNo,
		"leaf_hashes": leafHashes,
	})
	if err != nil {
		return Root{}, err
	}
	signature, err := canonical.Hash(map[string]any{
		"root_hash": rootHash,
		"signer": signer,
		"generated_at": generatedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		return Root{}, err
	}
	return Root{
		TenantID: tenantID,
		RootID: fmt.Sprintf("root_%s_%d_%d", tenantID, events[0].SequenceNo, events[len(events)-1].SequenceNo),
		FromSequenceNo: events[0].SequenceNo,
		ToSequenceNo: events[len(events)-1].SequenceNo,
		RootHash: rootHash,
		GeneratedAt: generatedAt,
		Signature: signature,
	}, nil
}

func eventHash(event Event) (string, error) {
	if event.TenantID == "" || event.SequenceNo <= 0 || event.EventType == "" {
		return "", errors.New("audit event is missing required fields")
	}
	payload := map[string]any{
		"tenant_id":        event.TenantID,
		"sequence_no":      event.SequenceNo,
		"event_id":         event.EventID,
		"invocation_id":    event.InvocationID,
		"event_type":       event.EventType,
		"actor_type":       event.ActorType,
		"actor_id":         event.ActorID,
		"safe_reason_code": event.SafeReasonCode,
		"redacted_payload": event.RedactedPayload,
		"previous_hash":    event.PreviousHash,
		"occurred_at":      event.OccurredAt.Format(time.RFC3339Nano),
	}
	return canonical.Hash(payload)
}
