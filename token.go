// Package auth is responsible for managing authentication and authorization.
package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type (
	contextKey int
	tokenType  string
)

const (
	tokenAccessAud  tokenType = "access"
	tokenRefreshAud tokenType = "refresh"
	headerKey                 = "Authorization"
	headerTokenType           = "Bearer "
	contextTokenKey           = contextKey(1)
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

// TokenOption is a token service creation option.
type TokenOption func(*TokenService)

// WithIssuer sets the token iss claim.
func WithIssuer(iss string) TokenOption {
	return func(ts *TokenService) {
		ts.issuer = iss
	}
}

// WithAudience sets the token aud claim.
func WithAudience(aud string) TokenOption {
	return func(ts *TokenService) {
		ts.audience = aud
	}
}

// WithAccessTimeout sets the access token timeout.
// Defaults to 15 minutes.
func WithAccessTimeout(timeout time.Duration) TokenOption {
	return func(ts *TokenService) {
		ts.accessTimeout = timeout
	}
}

// WithRefreshTimeout sets the refresh token timeout.
// Defaults to 30 days.
func WithRefreshTimeout(timeout time.Duration) TokenOption {
	return func(ts *TokenService) {
		ts.refreshTimeout = timeout
	}
}

// WithIDGenerator sets the function to set token ids.
// Defaults to uuid.NewString.
func WithIDGenerator(generator func() string) TokenOption {
	return func(ts *TokenService) {
		ts.idGenerator = generator
	}
}

// TokenService implements a standard JWT auth service.
type TokenService struct {
	signMethod     string
	signKey        *rsa.PrivateKey
	verifyKey      *rsa.PublicKey
	issuer         string
	audience       string
	accessTimeout  time.Duration
	refreshTimeout time.Duration
	idGenerator    func() string
}

// NewTokenService creates a new TokenService.
func NewTokenService(publicKey []byte, privateKey []byte, opts ...TokenOption) (*TokenService, error) {
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, rsaKeyError(err)
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, rsaKeyError(err)
	}

	service := &TokenService{
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
func (s *TokenService) ParseAccessToken(tokenString string) (*jwt.Token, error) {
	return s.parseToken(tokenString, tokenAccessAud)
}

// ParseRefreshToken verifies and transforms a given token string into a refresh JWT.
func (s *TokenService) ParseRefreshToken(tokenString string) (*jwt.Token, error) {
	return s.parseToken(tokenString, tokenRefreshAud)
}

func (s *TokenService) parseToken(tokenString string, tokenTypAud tokenType) (*jwt.Token, error) {
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
func (s *TokenService) GenerateAccessToken(sub string) (string, error) {
	return s.generateToken(sub, tokenAccessAud)
}

// GenerateRefreshToken creates and signes a new refresh JWT.
func (s *TokenService) GenerateRefreshToken(sub string) (string, error) {
	return s.generateToken(sub, tokenRefreshAud)
}

func (s *TokenService) generateToken(sub string, tokenTypeAud tokenType) (string, error) {
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

// FromHeader retrieves a token string from the given headers, if it exists.
func (s *TokenService) FromHeader(header http.Header) (string, bool) {
	bearer := header[headerKey]
	if bearer == nil || len(bearer) != 1 {
		return "", false
	}

	token, ok := strings.CutPrefix(bearer[0], headerTokenType)
	if !ok {
		return "", false
	}

	return token, true
}
