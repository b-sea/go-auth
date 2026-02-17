package jwt

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

var _ Signer = (*RS256)(nil)

// RS256 implements an RS256 JWT signer.
type RS256 struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewRS256 creates a new RS256 JWT signer.
func NewRS256(publicKey []byte, privateKey []byte) (*RS256, error) {
	public, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, rsaKeyError(err)
	}

	private, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, rsaKeyError(err)
	}

	return &RS256{
		publicKey:  public,
		privateKey: private,
	}, nil
}

// Algorithm returns the signing algorithm.
func (s *RS256) Algorithm() string {
	return "RS256"
}

// SignKey returns the sign key.
func (s *RS256) SignKey() any {
	return s.privateKey
}

// VerifyKey returns the verify key.
func (s *RS256) VerifyKey() any {
	return s.publicKey
}
