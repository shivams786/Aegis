package ratelimit

import (
	"errors"
	"testing"
	"time"
)

func TestLimiterReturnsRetryMetadata(t *testing.T) {
	limiter := NewLimiter()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	limiter.SetRule("agent:tool", Rule{Limit: 1, Window: time.Minute, Strict: true})

	if _, err := limiter.Check("agent:tool"); err != nil {
		t.Fatalf("first check: %v", err)
	}
	decision, err := limiter.Check("agent:tool")
	if !errors.Is(err, ErrLimited) {
		t.Fatalf("expected limited error, got %v", err)
	}
	if decision.RetryAfter <= 0 {
		t.Fatalf("expected retry metadata, got %#v", decision)
	}
}
