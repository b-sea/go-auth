// Package jwt implements JWT token management.
package jwt

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/b-sea/go-auth/token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	defaultTimeout        = 15 * time.Minute
	defaultLeeway         = 30 * time.Second
	tokenAccessTypeClaim  = "ACCESS"
	tokenRefreshTypeClaim = "REFRESH"
)

// Signer defines functions required to sign a JWT.
type Signer interface {
	Algorithm() string
	SignKey() any
	VerifyKey() any
}

var (
	_ token.Accessor  = (*Service)(nil)
	_ token.Refresher = (*Service)(nil)
)

// Service is a JWT service.
type Service struct {
	issuer       string
	timeout      time.Duration
	leeway       time.Duration
	signer       Signer
	newTokenID   func() string
	newTimestamp func() time.Time
}

// NewService creates a new JWT service.
func NewService(issuer string, signer Signer, options ...Option) (*Service, error) {
	if issuer == "" {
		return nil, ErrEmptyTokenIssuer
	}

	if jwt.GetSigningMethod(signer.Algorithm()) == nil {
		return nil, unknownSignAlgorithmError(signer.Algorithm())
	}

	service := &Service{
		issuer:       issuer,
		timeout:      defaultTimeout,
		leeway:       defaultLeeway,
		signer:       signer,
		newTokenID:   uuid.NewString,
		newTimestamp: time.Now,
	}

	for _, option := range options {
		option(service)
	}

	return service, nil
}

type accessClaims struct {
	jwt.RegisteredClaims

	Type   string           `json:"typ,omitempty"`
	Scopes jwt.ClaimStrings `json:"scp,omitempty"`
}

// Validate access JWT claim data.
func (a accessClaims) Validate() error {
	errs := make([]string, 0)

	if a.Type == "" {
		errs = append(errs, fmt.Sprintf("%v: typ claim is required", jwt.ErrTokenRequiredClaimMissing))
	} else if a.Type != tokenAccessTypeClaim {
		errs = append(errs, ErrTokenInvalidType.Error())
	}

	if a.ID == "" {
		errs = append(errs, fmt.Sprintf("%v: jti claim is required", jwt.ErrTokenRequiredClaimMissing))
	}

	if a.Subject == "" {
		errs = append(errs, fmt.Sprintf("%v: sub claim is required", jwt.ErrTokenRequiredClaimMissing))
	}

	if len(errs) == 0 {
		return nil
	}

	return errors.New(strings.Join(errs, ", ")) //nolint: err113
}

// NewAccessToken creates a new access token for the given claims.
func (s *Service) NewAccessToken(claims token.AccessClaims) token.Payload {
	timestamp := s.newTimestamp()

	generated := jwt.NewWithClaims(
		jwt.GetSigningMethod(s.signer.Algorithm()),
		&accessClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        s.newTokenID(),
				Issuer:    s.issuer,
				Subject:   claims.Subject(),
				ExpiresAt: jwt.NewNumericDate(timestamp.Add(s.timeout)),
				NotBefore: jwt.NewNumericDate(timestamp),
				IssuedAt:  jwt.NewNumericDate(timestamp),
			},
			Type:   tokenAccessTypeClaim,
			Scopes: claims.Scopes(),
		},
	)

	signed, _ := generated.SignedString(s.signer.SignKey())

	return token.Payload{
		Token:     signed,
		ExpiresIn: int(s.timeout.Seconds()),
	}
}

// ParseAccessClaims parses, validates, and verifies the given access token and returns the claims.
func (s *Service) ParseAccessClaims(accessToken string) (token.AccessClaims, error) {
	var claims accessClaims

	_, err := jwt.ParseWithClaims(
		accessToken,
		&claims,
		func(*jwt.Token) (any, error) {
			return s.signer.VerifyKey(), nil
		},
		jwt.WithIssuer(s.issuer),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithNotBeforeRequired(),
		jwt.WithValidMethods([]string{s.signer.Algorithm()}),
		jwt.WithLeeway(s.leeway),
	)
	if err != nil {
		return token.AccessClaims{}, tokenParseError(err)
	}

	return token.NewAccessClaims(claims.Subject, claims.Scopes), nil
}

type refreshClaims struct {
	jwt.RegisteredClaims

	Type string `json:"typ,omitempty"`
}

// Validate refresh JWT claim data.
func (a refreshClaims) Validate() error {
	errs := make([]string, 0)

	if a.Type == "" {
		errs = append(errs, fmt.Sprintf("%v: typ claim is required", jwt.ErrTokenRequiredClaimMissing))
	} else if a.Type != tokenRefreshTypeClaim {
		errs = append(errs, ErrTokenInvalidType.Error())
	}

	if a.ID == "" {
		errs = append(errs, fmt.Sprintf("%v: jti claim is required", jwt.ErrTokenRequiredClaimMissing))
	}

	if a.Subject == "" {
		errs = append(errs, fmt.Sprintf("%v: sub claim is required", jwt.ErrTokenRequiredClaimMissing))
	}

	if len(errs) == 0 {
		return nil
	}

	return errors.New(strings.Join(errs, ", ")) //nolint: err113
}

// NewRefreshToken creates a new refresh token for the given subject.
func (s *Service) NewRefreshToken(subject string) token.Payload {
	timestamp := s.newTimestamp()

	generated := jwt.NewWithClaims(
		jwt.GetSigningMethod(s.signer.Algorithm()),
		&refreshClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        s.newTokenID(),
				Issuer:    s.issuer,
				Subject:   subject,
				ExpiresAt: jwt.NewNumericDate(timestamp.Add(s.timeout)),
				NotBefore: jwt.NewNumericDate(timestamp),
				IssuedAt:  jwt.NewNumericDate(timestamp),
			},
			Type: tokenRefreshTypeClaim,
		},
	)

	signed, _ := generated.SignedString(s.signer.SignKey())

	return token.Payload{
		Token:     signed,
		ExpiresIn: int(s.timeout.Seconds()),
	}
}

// ParseRefreshSubject parses, validates, and verifies the given refresh token and returns the subject.
func (s *Service) ParseRefreshSubject(refreshToken string) (string, error) {
	var claims refreshClaims

	_, err := jwt.ParseWithClaims(
		refreshToken,
		&claims,
		func(*jwt.Token) (any, error) {
			return s.signer.VerifyKey(), nil
		},
		jwt.WithIssuer(s.issuer),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithNotBeforeRequired(),
		jwt.WithValidMethods([]string{s.signer.Algorithm()}),
		jwt.WithLeeway(s.leeway),
	)
	if err != nil {
		return "", tokenParseError(err)
	}

	return claims.Subject, nil
}
