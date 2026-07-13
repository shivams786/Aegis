package outbox

import (
	"errors"
	"testing"
)

type failingPublisher struct{}

func (failingPublisher) Publish(Event) error { return errors.New("nats unavailable") }

type successPublisher struct{}

func (successPublisher) Publish(Event) error { return nil }

func TestOutboxDeadLettersAfterRetriesAndCanReplay(t *testing.T) {
	store := NewStore()
	event, err := store.Add(Event{EventID: "evt_1", TenantID: "tenant_acme", AggregateID: "inv_1", EventType: "InvocationSucceeded"})
	if err != nil {
		t.Fatalf("add event: %v", err)
	}
	store.PublishPending(failingPublisher{}, 2)
	store.PublishPending(failingPublisher{}, 2)
	if !store.events[event.EventID].DeadLettered {
		t.Fatal("expected event to be dead-lettered")
	}
	if !store.Replay(event.EventID) {
		t.Fatal("expected replay to find event")
	}
	if published := store.PublishPending(successPublisher{}, 2); published != 1 {
		t.Fatalf("expected replay publish, got %d", published)
	}
}
