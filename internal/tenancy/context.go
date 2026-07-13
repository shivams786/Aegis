package tenancy

import (
	"context"
	"errors"
)

type contextKey struct{}

func ContextWithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, contextKey{}, tenantID)
}

func TenantID(ctx context.Context) (string, error) {
	tenantID, ok := ctx.Value(contextKey{}).(string)
	if !ok || tenantID == "" {
		return "", errors.New("tenant context is missing")
	}
	return tenantID, nil
}
