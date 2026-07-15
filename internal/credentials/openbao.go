package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type OpenBaoProvider struct {
	Address string
	Token   string
	Mount   string
	Client  *http.Client
	Now     func() time.Time
}

func (p OpenBaoProvider) Issue(scope Scope, ttl time.Duration) (Credential, error) {
	if p.Address == "" || p.Token == "" {
		return Credential{}, errors.New("openbao provider is not configured")
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	now := time.Now().UTC()
	if p.Now != nil {
		now = p.Now().UTC()
	}
	token, err := randomToken()
	if err != nil {
		return Credential{}, err
	}
	credential := Credential{Token: token, Scope: scope, ExpiresAt: now.Add(ttl)}
	if err := p.writeCredential(credential); err != nil {
		return Credential{}, err
	}
	return credential, nil
}

func (p OpenBaoProvider) Validate(token string, required Scope) error {
	if p.Address == "" || p.Token == "" {
		return errors.New("openbao provider is not configured")
	}
	credential, err := p.readCredential(token)
	if err != nil {
		return err
	}
	if p.Now != nil {
		now := p.Now().UTC()
		if !now.Before(credential.ExpiresAt) {
			return errors.New("credential is expired")
		}
	} else if !time.Now().UTC().Before(credential.ExpiresAt) {
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

func (p OpenBaoProvider) writeCredential(credential Credential) error {
	body, err := json.Marshal(map[string]any{"data": credential})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, p.url("/v1/"+p.mount()+"/data/aegis/credentials/"+credential.Token), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", p.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("write openbao credential: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("openbao write returned status %d", resp.StatusCode)
	}
	return nil
}

func (p OpenBaoProvider) readCredential(token string) (Credential, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, p.url("/v1/"+p.mount()+"/data/aegis/credentials/"+token), nil)
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("X-Vault-Token", p.Token)
	resp, err := p.client().Do(req)
	if err != nil {
		return Credential{}, fmt.Errorf("read openbao credential: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Credential{}, fmt.Errorf("openbao read returned status %d", resp.StatusCode)
	}
	var payload struct {
		Data struct {
			Data Credential `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return Credential{}, err
	}
	return payload.Data.Data, nil
}

func (p OpenBaoProvider) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return http.DefaultClient
}

func (p OpenBaoProvider) mount() string {
	if p.Mount == "" {
		return "secret"
	}
	return p.Mount
}

func (p OpenBaoProvider) url(path string) string {
	return p.Address + path
}
