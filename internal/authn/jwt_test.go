package authn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

const testKeyID = "test-key-1"

func TestValidatorAcceptsValidActingIdentity(t *testing.T) {
	validator, privateKey, now := newTestValidator(t)
	token := signToken(t, privateKey, testKeyID, "RS256", validClaims(now))

	identity, err := validator.AuthenticateBearer("Bearer " + token)
	if err != nil {
		t.Fatalf("expected token to authenticate: %v", err)
	}
	if identity.TenantID != "tenant_acme" {
		t.Fatalf("unexpected tenant: %s", identity.TenantID)
	}
	if identity.Subject.ID != "user_123" || identity.Subject.Type != PrincipalHuman {
		t.Fatalf("unexpected subject: %#v", identity.Subject)
	}
	if identity.Agent.ID != "agent_refund_assistant" || identity.Agent.ClientID != "refund-agent-client" {
		t.Fatalf("unexpected agent: %#v", identity.Agent)
	}
	if identity.Delegation.ID != "dlg_789" || identity.Delegation.Depth != 1 {
		t.Fatalf("unexpected delegation: %#v", identity.Delegation)
	}
}

func TestValidatorRejectsAlgNone(t *testing.T) {
	validator, _, now := newTestValidator(t)
	token := unsignedToken(t, testKeyID, validClaims(now))

	assertRejects(t, validator, token, "alg=none")
}

func TestValidatorRejectsUnknownKeyID(t *testing.T) {
	validator, privateKey, now := newTestValidator(t)
	token := signToken(t, privateKey, "unknown-key", "RS256", validClaims(now))

	assertRejects(t, validator, token, "kid is unknown")
}

func TestValidatorRejectsWrongIssuer(t *testing.T) {
	validator, privateKey, now := newTestValidator(t)
	claims := validClaims(now)
	claims["iss"] = "https://issuer.evil.example/realms/aegis"
	token := signToken(t, privateKey, testKeyID, "RS256", claims)

	assertRejects(t, validator, token, "issuer")
}

func TestValidatorRejectsWrongAudience(t *testing.T) {
	validator, privateKey, now := newTestValidator(t)
	claims := validClaims(now)
	claims["aud"] = []string{"downstream-payments"}
	token := signToken(t, privateKey, testKeyID, "RS256", claims)

	assertRejects(t, validator, token, "audience")
}

func TestValidatorRejectsExpiredToken(t *testing.T) {
	validator, privateKey, now := newTestValidator(t)
	claims := validClaims(now)
	claims["exp"] = now.Add(-time.Minute).Unix()
	token := signToken(t, privateKey, testKeyID, "RS256", claims)

	assertRejects(t, validator, token, "expired")
}

func TestValidatorRejectsMissingTenant(t *testing.T) {
	validator, privateKey, now := newTestValidator(t)
	claims := validClaims(now)
	delete(claims, "tenant_id")
	token := signToken(t, privateKey, testKeyID, "RS256", claims)

	assertRejects(t, validator, token, "tenant_id")
}

func TestValidatorRejectsUnknownPrincipalType(t *testing.T) {
	validator, privateKey, now := newTestValidator(t)
	claims := validClaims(now)
	claims["subject_type"] = "superuser"
	token := signToken(t, privateKey, testKeyID, "RS256", claims)

	assertRejects(t, validator, token, "subject.type")
}

func TestValidatorRejectsMalformedScopes(t *testing.T) {
	validator, privateKey, now := newTestValidator(t)
	claims := validClaims(now)
	claims["scp"] = []string{"aegis.invoke", "bad scope"}
	token := signToken(t, privateKey, testKeyID, "RS256", claims)

	assertRejects(t, validator, token, "scope")
}

func TestValidatorRejectsMissingBearerHeader(t *testing.T) {
	validator, _, _ := newTestValidator(t)

	_, err := validator.AuthenticateBearer("")
	if err == nil || !strings.Contains(err.Error(), "bearer") {
		t.Fatalf("expected missing bearer header to fail, got %v", err)
	}
}

func newTestValidator(t *testing.T) (*Validator, *rsa.PrivateKey, time.Time) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	jwks := JWKSet{Keys: []JWK{{
		KeyType:   "RSA",
		KeyID:     testKeyID,
		Use:       "sig",
		Algorithm: "RS256",
		N:         base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
	}}}
	validator, err := NewValidatorFromJWKS(ValidatorConfig{
		Issuer:             "http://localhost:8081/realms/aegis",
		Audiences:          []string{"aegis-gateway"},
		RequiredScopes:     []string{"aegis.invoke"},
		ApprovedAlgorithms: []string{"RS256"},
		RequiredTokenType:  "Bearer",
		ClockSkew:          0,
	}, jwks)
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	validator.now = func() time.Time { return now }
	return validator, privateKey, now
}

func validClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":                   "http://localhost:8081/realms/aegis",
		"sub":                   "user_123",
		"aud":                   []string{"aegis-gateway"},
		"exp":                   now.Add(time.Hour).Unix(),
		"nbf":                   now.Add(-time.Minute).Unix(),
		"iat":                   now.Add(-time.Minute).Unix(),
		"typ":                   "Bearer",
		"tenant_id":             "tenant_acme",
		"subject_type":          "human",
		"groups":                []string{"support"},
		"roles":                 []string{"refund_operator"},
		"client_id":             "refund-agent-client",
		"scope":                 "openid profile aegis.invoke",
		"agent_id":              "agent_refund_assistant",
		"agent_trust_level":     3,
		"agent_owner_id":        "user_123",
		"agent_client_id":       "refund-agent-client",
		"delegation_id":         "dlg_789",
		"delegation_depth":      1,
		"delegation_purpose":    "customer_support",
		"delegation_audience":   "aegis",
		"delegation_expires_at": now.Add(time.Hour).Format(time.RFC3339),
	}
}

func signToken(t *testing.T, privateKey *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": alg, "kid": kid, "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signed := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func unsignedToken(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "none", "kid": kid, "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + ".x"
}

func assertRejects(t *testing.T, validator *Validator, token, contains string) {
	t.Helper()
	_, err := validator.AuthenticateBearer("Bearer " + token)
	if err == nil {
		t.Fatal("expected token to be rejected")
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("expected error to contain %q, got %v", contains, err)
	}
}
