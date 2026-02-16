package auth

import (
	"github.com/b-sea/go-auth/token"
)

// Option is used for configuring auth handlers.
type Option func(c *handleConfig)

// WithAuthZ will enable access management on auth handlers.
func WithAuthZ(authZ token.Authorizer) Option {
	return func(c *handleConfig) {
		c.log.Debug().Msg("authorization enabled")
		c.authZ = authZ
	}
}

// WithRefreshToken will enable refresh tokens on auth handlers.
func WithRefreshToken(refresh token.Refresher) Option {
	return func(c *handleConfig) {
		c.refresh = refresh
	}
}

// WithAddlAuthN adds an additional authenticator and associated handlers.
func WithAddlAuthN(authN Authenticator) Option {
	return func(c *handleConfig) {
		c.authNs = append(c.authNs, authN)
	}
}
