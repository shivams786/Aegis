package credentials

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

type Scope struct {
	TenantID    string `json:"tenant_id"`
	ToolID      string `json:"tool_id"`
	Action      string `json:"action"`
	Resource    string `json:"resource"`
	AmountMinor int64  `json:"amount_minor,omitempty"`
}

type Credential struct {
	Token     string    `json:"token"`
	Scope     Scope     `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Provider interface {
	Issue(scope Scope, ttl time.Duration) (Credential, error)
	Validate(token string, required Scope) error
}

type MemoryProvider struct {
	mu    sync.Mutex
	creds map[string]Credential
	now   func() time.Time
}

func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{
		creds: make(map[string]Credential),
		now:   func() time.Time { return time.Now().UTC() },
	}
}

func (p *MemoryProvider) Issue(scope Scope, ttl time.Duration) (Credential, error) {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	token, err := randomToken()
	if err != nil {
		return Credential{}, err
	}
	credential := Credential{Token: token, Scope: scope, ExpiresAt: p.now().Add(ttl)}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.creds[token] = credential
	return credential, nil
}

func (p *MemoryProvider) Validate(token string, required Scope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	credential, ok := p.creds[token]
	if !ok {
		return errors.New("credential is unknown")
	}
	if !p.now().Before(credential.ExpiresAt) {
		return errors.New("credential is expired")
	}
	if credential.Scope.TenantID != required.TenantID ||
		credential.Scope.ToolID != required.ToolID ||
		credential.Scope.Action != required.Action ||
		credential.Scope.Resource != required.Resource {
		return errors.New("credential scope does not match requested operation")
	}
	if required.AmountMinor > 0 && credential.Scope.AmountMinor > 0 && required.AmountMinor > credential.Scope.AmountMinor {
		return errors.New("credential amount scope is too narrow")
	}
	return nil
}

func randomToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "cred_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
