package auth

import (
	"context"

	"github.com/b-sea/go-auth/token"
	"github.com/rs/zerolog"
)

// Option is used for configuring auth handlers.
type Option func(ctx context.Context, cfg *handleConfig)

// WithAuthZ will enable access management on auth handlers.
func WithAuthZ(authZ token.Authorizer) Option {
	return func(ctx context.Context, cfg *handleConfig) {
		zerolog.Ctx(ctx).Debug().Msg("authorization enabled")

		cfg.authZ = authZ
	}
}

// WithRefreshToken will enable refresh tokens on auth handlers.
func WithRefreshToken(refresh token.Refresher) Option {
	return func(_ context.Context, cfg *handleConfig) {
		cfg.refresh = refresh
	}
}

// WithAddlAuthN adds an additional authenticator and associated handlers.
func WithAddlAuthN(authN Authenticator) Option {
	return func(_ context.Context, cfg *handleConfig) {
		cfg.authNs = append(cfg.authNs, authN)
	}
}
