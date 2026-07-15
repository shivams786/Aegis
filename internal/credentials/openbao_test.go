package credentials

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOpenBaoProviderWritesAndReadsScopedCredential(t *testing.T) {
	stored := map[string]Credential{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "dev-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		token := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		switch r.Method {
		case http.MethodPost:
			var payload struct {
				Data Credential `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			stored[token] = payload.Data
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": stored[token]}})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	provider := OpenBaoProvider{Address: server.URL, Token: "dev-token", Now: func() time.Time { return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC) }}
	credential, err := provider.Issue(Scope{TenantID: "tenant_acme", ToolID: "payments.refund", Action: "refund", Resource: "customer:CUST-1042", AmountMinor: 50000}, time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := provider.Validate(credential.Token, credential.Scope); err != nil {
		t.Fatalf("validate: %v", err)
	}
}
