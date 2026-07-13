package authn

import (
	"context"
	"errors"
	"net/http"

	"github.com/aegis/aegis/internal/config"
)

func NewValidatorFromConfig(ctx context.Context, cfg config.AuthConfig, client *http.Client) (*Validator, error) {
	validatorConfig := ValidatorConfig{
		Issuer:              cfg.Issuer,
		Audiences:           cfg.Audiences,
		RequiredScopes:      cfg.RequiredScopes,
		ApprovedAlgorithms:  cfg.ApprovedAlgorithms,
		RequiredTokenType:   cfg.RequiredTokenType,
		ClockSkew:           cfg.ClockSkew,
		ProtectedResourceID: cfg.ProtectedResourceID,
	}

	switch {
	case cfg.JWKSJSON != "":
		return NewValidatorFromJSON(validatorConfig, []byte(cfg.JWKSJSON))
	case cfg.JWKSFile != "":
		return NewValidatorFromFile(validatorConfig, cfg.JWKSFile)
	case cfg.JWKSURL != "":
		return NewValidatorFromURL(ctx, validatorConfig, cfg.JWKSURL, client)
	default:
		return nil, errors.New("no jwks source configured")
	}
}
