package outbox

import (
	"errors"
	"sync"
	"time"
)

type Event struct {
	EventID          string         `json:"event_id"`
	TenantID         string         `json:"tenant_id"`
	AggregateID      string         `json:"aggregate_id"`
	AggregateVersion int64          `json:"aggregate_version"`
	EventType        string         `json:"event_type"`
	Payload          map[string]any `json:"payload"`
	TraceContext     map[string]any `json:"trace_context"`
	SchemaVersion    int            `json:"schema_version"`
	OccurredAt       time.Time      `json:"occurred_at"`
	PublishedAt      *time.Time     `json:"published_at,omitempty"`
	DeliveryAttempts int            `json:"delivery_attempts"`
	LastError         string         `json:"last_error,omitempty"`
	DeadLettered     bool           `json:"dead_lettered"`
}

type Publisher interface {
	Publish(event Event) error
}

type Store struct {
	mu     sync.Mutex
	events map[string]Event
	now    func() time.Time
}

func NewStore() *Store {
	return &Store{events: make(map[string]Event), now: func() time.Time { return time.Now().UTC() }}
}

func (s *Store) Add(event Event) (Event, error) {
	if event.EventID == "" || event.TenantID == "" || event.AggregateID == "" || event.EventType == "" {
		return Event{}, errors.New("outbox event missing required fields")
	}
	if event.SchemaVersion == 0 {
		event.SchemaVersion = 1
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.events[event.EventID]; ok {
		return existing, nil
	}
	s.events[event.EventID] = event
	return event, nil
}

func (s *Store) PublishPending(publisher Publisher, maxAttempts int) int {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	s.mu.Lock()
	pending := make([]Event, 0)
	for _, event := range s.events {
		if event.PublishedAt == nil && !event.DeadLettered {
			pending = append(pending, event)
		}
	}
	s.mu.Unlock()
	published := 0
	for _, event := range pending {
		if err := publisher.Publish(event); err != nil {
			s.markFailed(event.EventID, err, maxAttempts)
			continue
		}
		s.markPublished(event.EventID)
		published++
	}
	return published
}

func (s *Store) markPublished(eventID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	event := s.events[eventID]
	now := s.now()
	event.PublishedAt = &now
	event.LastError = ""
	event.DeliveryAttempts++
	s.events[eventID] = event
}

func (s *Store) markFailed(eventID string, err error, maxAttempts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	event := s.events[eventID]
	event.DeliveryAttempts++
	event.LastError = err.Error()
	if event.DeliveryAttempts >= maxAttempts {
		event.DeadLettered = true
	}
	s.events[eventID] = event
}

func (s *Store) Replay(eventID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.events[eventID]
	if !ok {
		return false
	}
	event.PublishedAt = nil
	event.DeadLettered = false
	event.LastError = ""
	s.events[eventID] = event
	return true
}
