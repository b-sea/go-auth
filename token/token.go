// Package token is responsible for managing tokens.
package token

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type tokenType string

const (
	accessAud  tokenType = "access"
	refreshAud tokenType = "refresh"
)

var (
	// Timestamp is a function to generate a timestamp value.
	Timestamp = time.Now //nolint: gochecknoglobals

	// ErrRSAKey is raised when RSA keys encounter an error.
	ErrRSAKey = errors.New("rsa key error")

	// ErrJWTClaim is raised when a JWT claim is incorrect.
	ErrJWTClaim = errors.New("jwt claims error")
)

func rsaKeyError(value interface{}) error {
	return fmt.Errorf("%w: %v", ErrRSAKey, value)
}

func jwtClaimError(value interface{}) error {
	return fmt.Errorf("%w: %v", ErrJWTClaim, value)
}

// Option is a token service creation option.
type Option func(*Service)

// WithIssuer sets the token iss claim.
func WithIssuer(iss string) Option {
	return func(ts *Service) {
		ts.issuer = iss
	}
}

// WithAudience sets the token aud claim.
func WithAudience(aud string) Option {
	return func(ts *Service) {
		ts.audience = aud
	}
}

// WithAccessTimeout sets the access token timeout.
// Defaults to 15 minutes.
func WithAccessTimeout(timeout time.Duration) Option {
	return func(ts *Service) {
		ts.accessTimeout = timeout
	}
}

// WithRefreshTimeout sets the refresh token timeout.
// Defaults to 30 days.
func WithRefreshTimeout(timeout time.Duration) Option {
	return func(ts *Service) {
		ts.refreshTimeout = timeout
	}
}

// WithIDGenerator sets the function to set token ids.
// Defaults to uuid.NewString.
func WithIDGenerator(generator func() string) Option {
	return func(ts *Service) {
		ts.idGenerator = generator
	}
}

// Service implements a standard JWT auth service.
type Service struct {
	signMethod     string
	signKey        *rsa.PrivateKey
	verifyKey      *rsa.PublicKey
	issuer         string
	audience       string
	accessTimeout  time.Duration
	refreshTimeout time.Duration
	idGenerator    func() string
}

// NewService creates a new Service.
func NewService(publicKey []byte, privateKey []byte, opts ...Option) (*Service, error) {
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, rsaKeyError(err)
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, rsaKeyError(err)
	}

	service := &Service{
		signMethod:     "RS256",
		verifyKey:      verifyKey,
		signKey:        signKey,
		accessTimeout:  15 * time.Minute, //nolint: gomnd
		refreshTimeout: 30 * 24 * time.Hour,
		idGenerator:    uuid.NewString,
	}

	for _, opt := range opts {
		opt(service)
	}

	return service, nil
}

// ParseAccessToken verifies and transforms a given token string into an access JWT.
func (s *Service) ParseAccessToken(tokenString string) (*jwt.Token, error) {
	return s.parseToken(tokenString, accessAud)
}

// ParseRefreshToken verifies and transforms a given token string into a refresh JWT.
func (s *Service) ParseRefreshToken(tokenString string) (*jwt.Token, error) {
	return s.parseToken(tokenString, refreshAud)
}

func (s *Service) parseToken(tokenString string, tokenTypAud tokenType) (*jwt.Token, error) {
	var claims jwt.RegisteredClaims

	options := []jwt.ParserOption{
		jwt.WithAudience(string(tokenTypAud)),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{s.signMethod}),
	}

	if s.audience != "" {
		options = append(options, jwt.WithAudience(s.audience))
	}

	if s.issuer != "" {
		options = append(options, jwt.WithIssuer(s.issuer))
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(*jwt.Token) (interface{}, error) {
			return s.verifyKey, nil
		},
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return token, nil
}

// GenerateAccessToken creates and signes a new access JWT.
func (s *Service) GenerateAccessToken(sub string) (string, error) {
	return s.generateToken(sub, accessAud)
}

// GenerateRefreshToken creates and signes a new refresh JWT.
func (s *Service) GenerateRefreshToken(sub string) (string, error) {
	return s.generateToken(sub, refreshAud)
}

func (s *Service) generateToken(sub string, tokenTypeAud tokenType) (string, error) {
	if sub == "" {
		return "", jwtClaimError("missing sub claim")
	}

	claims := jwt.RegisteredClaims{
		ID:        s.idGenerator(),
		Subject:   sub,
		Audience:  jwt.ClaimStrings([]string{string(tokenTypeAud)}),
		ExpiresAt: jwt.NewNumericDate(Timestamp().Add(s.accessTimeout)),
		IssuedAt:  jwt.NewNumericDate(Timestamp()),
	}

	if s.issuer != "" {
		claims.Issuer = s.issuer
	}

	if s.audience != "" {
		claims.Audience = append(claims.Audience, s.audience)
	}

	token := jwt.NewWithClaims(
		jwt.GetSigningMethod(s.signMethod),
		&claims,
	)

	signed, _ := token.SignedString(s.signKey)

	return signed, nil
}
