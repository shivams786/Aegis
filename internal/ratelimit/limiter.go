package ratelimit

import (
	"errors"
	"sync"
	"time"
)

var ErrLimited = errors.New("rate limit exceeded")

type Decision struct {
	Allowed    bool          `json:"allowed"`
	Limit      int           `json:"limit"`
	Remaining  int           `json:"remaining"`
	RetryAfter time.Duration `json:"retry_after"`
}

type Limiter struct {
	mu     sync.Mutex
	limits map[string]Rule
	events map[string][]time.Time
	now    func() time.Time
}

type Rule struct {
	Limit  int
	Window time.Duration
	Strict bool
}

func NewLimiter() *Limiter {
	return &Limiter{
		limits: make(map[string]Rule),
		events: make(map[string][]time.Time),
		now:    func() time.Time { return time.Now().UTC() },
	}
}

func (l *Limiter) SetRule(key string, rule Rule) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limits[key] = rule
}

func (l *Limiter) Check(key string) (Decision, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rule, ok := l.limits[key]
	if !ok || rule.Limit <= 0 || rule.Window <= 0 {
		return Decision{Allowed: true, Limit: 0, Remaining: 0}, nil
	}
	now := l.now()
	cutoff := now.Add(-rule.Window)
	events := l.events[key]
	kept := events[:0]
	for _, event := range events {
		if event.After(cutoff) {
			kept = append(kept, event)
		}
	}
	if len(kept) >= rule.Limit {
		retryAfter := kept[0].Add(rule.Window).Sub(now)
		l.events[key] = kept
		return Decision{Allowed: false, Limit: rule.Limit, Remaining: 0, RetryAfter: retryAfter}, ErrLimited
	}
	kept = append(kept, now)
	l.events[key] = kept
	return Decision{Allowed: true, Limit: rule.Limit, Remaining: rule.Limit - len(kept)}, nil
}
