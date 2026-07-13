package authn

import (
	"context"
	"errors"
)

type identityContextKey struct{}

func ContextWithIdentity(ctx context.Context, identity ActingIdentity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

func IdentityFromContext(ctx context.Context) (ActingIdentity, error) {
	identity, ok := ctx.Value(identityContextKey{}).(ActingIdentity)
	if !ok {
		return ActingIdentity{}, errors.New("acting identity is missing")
	}
	return identity, nil
}
