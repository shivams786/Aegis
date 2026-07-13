package authn

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

type ValidatorConfig struct {
	Issuer              string
	Audiences           []string
	RequiredScopes      []string
	ApprovedAlgorithms  []string
	RequiredTokenType   string
	ClockSkew           time.Duration
	ProtectedResourceID string
}

type Validator struct {
	cfg  ValidatorConfig
	keys map[string]verificationKey
	now  func() time.Time
}

type verificationKey struct {
	Algorithm string
	PublicKey *rsa.PublicKey
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use,omitempty"`
	Algorithm string `json:"alg,omitempty"`
	N         string `json:"n"`
	E         string `json:"e"`
}

type tokenHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type Claims struct {
	Issuer              string        `json:"iss"`
	Subject             string        `json:"sub"`
	Audience            audienceClaim `json:"aud"`
	ExpiresAt           int64         `json:"exp"`
	NotBefore           int64         `json:"nbf"`
	IssuedAt            int64         `json:"iat"`
	TokenType           string        `json:"typ"`
	AlternativeType     string        `json:"token_type"`
	TenantID            string        `json:"tenant_id"`
	SubjectType         PrincipalType `json:"subject_type"`
	Groups              []string      `json:"groups"`
	Roles               []string      `json:"roles"`
	RealmAccess         realmAccess   `json:"realm_access"`
	ClientID            string        `json:"client_id"`
	AuthorizedParty     string        `json:"azp"`
	Scope               string        `json:"scope"`
	Scopes              []string      `json:"scp"`
	AgentID             string        `json:"agent_id"`
	AgentTrustLevel     int           `json:"agent_trust_level"`
	AgentOwnerID        string        `json:"agent_owner_id"`
	AgentClientID       string        `json:"agent_client_id"`
	DelegationID        string        `json:"delegation_id"`
	DelegationDepth     int           `json:"delegation_depth"`
	DelegationPurpose   string        `json:"delegation_purpose"`
	DelegationAudience  string        `json:"delegation_audience"`
	DelegationExpiresAt string        `json:"delegation_expires_at"`
}

type realmAccess struct {
	Roles []string `json:"roles"`
}

type audienceClaim []string

func (a *audienceClaim) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud must be a string or string array")
	}
	*a = many
	return nil
}

func NewValidatorFromJWKS(cfg ValidatorConfig, jwks JWKSet) (*Validator, error) {
	if strings.TrimSpace(cfg.RequiredTokenType) == "" {
		cfg.RequiredTokenType = "Bearer"
	}
	if cfg.ClockSkew < 0 {
		return nil, errors.New("clock skew must not be negative")
	}
	if len(cfg.ApprovedAlgorithms) == 0 {
		cfg.ApprovedAlgorithms = []string{"RS256"}
	}

	keys := make(map[string]verificationKey, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == "" {
			return nil, errors.New("jwk kid is required")
		}
		if jwk.KeyType != "RSA" {
			return nil, fmt.Errorf("unsupported jwk key type %q", jwk.KeyType)
		}
		if jwk.Algorithm != "" && !slices.Contains(cfg.ApprovedAlgorithms, jwk.Algorithm) {
			return nil, fmt.Errorf("jwk %q uses unapproved algorithm", jwk.KeyID)
		}
		publicKey, err := rsaPublicKey(jwk)
		if err != nil {
			return nil, fmt.Errorf("parse jwk %q: %w", jwk.KeyID, err)
		}
		keys[jwk.KeyID] = verificationKey{
			Algorithm: jwk.Algorithm,
			PublicKey: publicKey,
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks contains no usable keys")
	}

	return &Validator{cfg: cfg, keys: keys, now: func() time.Time { return time.Now().UTC() }}, nil
}

func NewValidatorFromJSON(cfg ValidatorConfig, jwksJSON []byte) (*Validator, error) {
	var jwks JWKSet
	if err := json.Unmarshal(jwksJSON, &jwks); err != nil {
		return nil, fmt.Errorf("parse jwks json: %w", err)
	}
	return NewValidatorFromJWKS(cfg, jwks)
}

func NewValidatorFromFile(cfg ValidatorConfig, path string) (*Validator, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read jwks file: %w", err)
	}
	return NewValidatorFromJSON(cfg, data)
}

func NewValidatorFromURL(ctx context.Context, cfg ValidatorConfig, url string, client *http.Client) (*Validator, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create jwks request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks returned status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read jwks body: %w", err)
	}
	return NewValidatorFromJSON(cfg, data)
}

func (v *Validator) AuthenticateBearer(header string) (ActingIdentity, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ActingIdentity{}, errors.New("authorization header must use bearer scheme")
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return ActingIdentity{}, errors.New("bearer token is empty")
	}
	return v.AuthenticateToken(token)
}

func (v *Validator) AuthenticateToken(token string) (ActingIdentity, error) {
	claims, err := v.Verify(token)
	if err != nil {
		return ActingIdentity{}, err
	}
	identity, err := claims.ActingIdentity()
	if err != nil {
		return ActingIdentity{}, err
	}
	return identity, nil
}

func (v *Validator) Verify(token string) (Claims, error) {
	if v == nil {
		return Claims{}, errors.New("jwt validator is not configured")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, errors.New("jwt must contain header, payload, and signature")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, errors.New("jwt header is not valid base64url")
	}
	var header tokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Claims{}, errors.New("jwt header is not valid json")
	}
	if strings.EqualFold(header.Algorithm, "none") {
		return Claims{}, errors.New("unsecured jwt alg=none is not allowed")
	}
	if !slices.Contains(v.cfg.ApprovedAlgorithms, header.Algorithm) {
		return Claims{}, fmt.Errorf("jwt algorithm %q is not approved", header.Algorithm)
	}
	if header.KeyID == "" {
		return Claims{}, errors.New("jwt kid is required")
	}
	key, ok := v.keys[header.KeyID]
	if !ok {
		return Claims{}, errors.New("jwt kid is unknown")
	}
	if key.Algorithm != "" && key.Algorithm != header.Algorithm {
		return Claims{}, errors.New("jwt algorithm does not match jwk")
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, errors.New("jwt signature is not valid base64url")
	}
	signed := parts[0] + "." + parts[1]
	if err := verifySignature(header.Algorithm, key.PublicKey, []byte(signed), signature); err != nil {
		return Claims{}, err
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, errors.New("jwt payload is not valid base64url")
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return Claims{}, fmt.Errorf("jwt payload is not valid claims json: %w", err)
	}
	if err := v.validateClaims(claims); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func (v *Validator) validateClaims(claims Claims) error {
	var errs []error
	now := v.now()
	if claims.Issuer != v.cfg.Issuer {
		errs = append(errs, errors.New("jwt issuer is not trusted"))
	}
	if !intersects([]string(claims.Audience), v.cfg.Audiences) {
		errs = append(errs, errors.New("jwt audience is not accepted"))
	}
	if claims.ExpiresAt == 0 || now.After(time.Unix(claims.ExpiresAt, 0).Add(v.cfg.ClockSkew)) {
		errs = append(errs, errors.New("jwt is expired"))
	}
	if claims.NotBefore != 0 && now.Add(v.cfg.ClockSkew).Before(time.Unix(claims.NotBefore, 0)) {
		errs = append(errs, errors.New("jwt is not active yet"))
	}
	if strings.TrimSpace(claims.TenantID) == "" {
		errs = append(errs, errors.New("jwt tenant_id is required"))
	}
	tokenType := claims.TokenType
	if tokenType == "" {
		tokenType = claims.AlternativeType
	}
	if tokenType != v.cfg.RequiredTokenType {
		errs = append(errs, errors.New("jwt token type is not accepted"))
	}
	scopes, err := claims.ScopeSet()
	if err != nil {
		errs = append(errs, err)
	} else {
		for _, required := range v.cfg.RequiredScopes {
			if !slices.Contains(scopes, required) {
				errs = append(errs, fmt.Errorf("jwt missing required scope %q", required))
			}
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c Claims) ScopeSet() ([]string, error) {
	values := make([]string, 0)
	if c.Scope != "" {
		for _, scope := range strings.Split(c.Scope, " ") {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				continue
			}
			if strings.ContainsAny(scope, "\t\r\n") {
				return nil, errors.New("jwt scopes are malformed")
			}
			values = append(values, scope)
		}
	}
	for _, scope := range c.Scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return nil, errors.New("jwt scp contains malformed scope")
		}
		values = append(values, scope)
	}
	return dedupe(values), nil
}

func (c Claims) ActingIdentity() (ActingIdentity, error) {
	delegationExpiry, err := parseOptionalTime(c.DelegationExpiresAt)
	if err != nil {
		return ActingIdentity{}, err
	}
	clientID := c.ClientID
	if clientID == "" {
		clientID = c.AuthorizedParty
	}
	agentClientID := c.AgentClientID
	if agentClientID == "" {
		agentClientID = clientID
	}
	roles := append([]string{}, c.Roles...)
	roles = append(roles, c.RealmAccess.Roles...)
	scopes, err := c.ScopeSet()
	if err != nil {
		return ActingIdentity{}, err
	}
	tokenType := c.TokenType
	if tokenType == "" {
		tokenType = c.AlternativeType
	}

	identity := ActingIdentity{
		TenantID: c.TenantID,
		Subject: Subject{
			Type:   c.SubjectType,
			ID:     c.Subject,
			Groups: dedupe(c.Groups),
			Roles:  dedupe(roles),
		},
		Agent: Agent{
			ID:         c.AgentID,
			TrustLevel: c.AgentTrustLevel,
			OwnerID:    c.AgentOwnerID,
			ClientID:   agentClientID,
		},
		Delegation: DelegationContext{
			ID:        c.DelegationID,
			Depth:     c.DelegationDepth,
			Purpose:   c.DelegationPurpose,
			Audience:  c.DelegationAudience,
			ExpiresAt: delegationExpiry,
		},
		ClientID:  clientID,
		TokenType: tokenType,
		Scopes:    scopes,
	}
	return identity, identity.Validate()
}

func verifySignature(algorithm string, publicKey *rsa.PublicKey, signed, signature []byte) error {
	switch algorithm {
	case "RS256":
		digest := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
			return errors.New("jwt signature is invalid")
		}
		return nil
	default:
		return fmt.Errorf("jwt algorithm %q is not implemented", algorithm)
	}
}

func rsaPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	modulusBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, errors.New("invalid rsa modulus")
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, errors.New("invalid rsa exponent")
	}
	exponent := new(big.Int).SetBytes(exponentBytes).Int64()
	if exponent <= 1 || exponent > int64(^uint(0)>>1) {
		return nil, errors.New("invalid rsa exponent value")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: int(exponent),
	}, nil
}

func parseOptionalTime(value string) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("delegation_expires_at must be RFC3339: %w", err)
	}
	return parsed.UTC(), nil
}

func intersects(left, right []string) bool {
	for _, l := range left {
		if slices.Contains(right, l) {
			return true
		}
	}
	return false
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
