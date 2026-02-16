// Package token defines auth token management.
package token

import (
	"slices"
	"strings"
)

// Authenticator defines functions required for authN.
type Authenticator interface {
	// Authenticate an input and return the authenticated subject.
	Authenticate(input any) (string, error)
}

// Authorizer defines functions required for authZ.
type Authorizer interface {
	// AccessClaims returns the authorization claims for the given subject.
	AccessClaims(subject string) (AccessClaims, error)
}

// Accessor defines functions required for access token management.
type Accessor interface {
	// NewAccessToken creates a new access token for the given claims.
	NewAccessToken(claims AccessClaims) Payload

	// ParseAccessClaims parses, validates, and verifies the given access token and returns the claims.
	ParseAccessClaims(accessToken string) (AccessClaims, error)
}

// AccessClaims are standardized data found in access tokens.
type AccessClaims struct {
	subject string
	scopes  []string
}

// NewAccessClaims creates new access claims.
func NewAccessClaims(subject string, scopes []string) AccessClaims {
	return AccessClaims{
		subject: subject,
		scopes:  scopes,
	}
}

// Subject returns the subject claim.
func (c AccessClaims) Subject() string {
	return c.subject
}

// Scopes returns the subject claim.
func (c AccessClaims) Scopes() []string {
	return c.scopes
}

// HasScope checks if the claims are authorized for the given scope.
func (c AccessClaims) HasScope(scope string) bool {
	return slices.ContainsFunc(
		c.scopes,
		func(s string) bool {
			return strings.EqualFold(scope, s)
		},
	)
}

// Refresher defines functions required for refresh token management.
type Refresher interface {
	// NewRefreshToken creates a new refresh token for the given subject.
	NewRefreshToken(subject string) Payload

	// ParseRefreshSubject parses, validates, and verifies the given refresh token and returns the subject.
	ParseRefreshSubject(refreshToken string) (string, error)
}

// Payload is generated token data.
type Payload struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expiresIn"`
}
