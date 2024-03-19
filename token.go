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
	"github.com/sirupsen/logrus"
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

// ITokenService defines all functions required for managing auth tokens.
type ITokenService interface {
	ParseAccessToken(tokenString string) (*jwt.Token, error)
	ParseRefreshToken(tokenString string) (*jwt.Token, error)
	GenerateAccessToken(sub string) (string, error)
	GenerateRefreshToken(sub string) (string, error)
	FromHeader(header http.Header) (string, bool)
}

// TokenConfig defines all fields required to create a TokenService.
type TokenConfig struct {
	SignMethod     string
	PublicKey      []byte
	PrivateKey     []byte
	Issuer         string
	Audience       string
	AccessTimeout  time.Duration
	RefreshTimeout time.Duration
	IDGenerator    func() string
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
func NewTokenService(config TokenConfig) (*TokenService, error) {
	if config.SignMethod != "RS256" {
		return nil, rsaKeyError("only sign method RS256 is currently supported")
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(config.PublicKey)
	if err != nil {
		return nil, rsaKeyError(err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(config.PrivateKey)
	if err != nil {
		return nil, rsaKeyError(err)
	}

	if config.Issuer == "" {
		logrus.Warn("No issuer defined for token service")
	}

	if config.Audience == "" {
		logrus.Warn("No audience defined for token service")
	}

	if config.IDGenerator == nil {
		config.IDGenerator = uuid.NewString
	}

	return &TokenService{
		signMethod:     config.SignMethod,
		verifyKey:      publicKey,
		signKey:        privateKey,
		issuer:         config.Issuer,
		audience:       config.Audience,
		accessTimeout:  config.AccessTimeout,
		refreshTimeout: config.RefreshTimeout,
		idGenerator:    config.IDGenerator,
	}, nil
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
