// Package provider defines and implements auth providers.
package provider

import "github.com/b-sea/go-auth/token"

// Provider defines functions required for auth providers.
type Provider[T any] interface {
	Ping() error
	Authenticate(input T)
	AuthenticationInput() T
	AccessClaims(subject string) (token.AccessClaims, error)
}
