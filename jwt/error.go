package jwt

import (
	"errors"
	"fmt"
)

// ErrUnknownSignAlgorithm, et al. are the errors raised by JWT management.
var (
	ErrUnknownSignAlgorithm = errors.New("unknown sign algorithm")
	ErrEmptyTokenIssuer     = errors.New("token issuer cannot be empty")
	ErrTokenInvalidType     = errors.New("token has an invalid type")
	ErrTokenParse           = errors.New("error parsing token")

	ErrRSAKey   = errors.New("rsa key error")
	ErrReadCert = errors.New("cert read error")
)

func unknownSignAlgorithmError(v any) error {
	return fmt.Errorf("%w: %v", ErrUnknownSignAlgorithm, v)
}

func tokenParseError(v any) error {
	return fmt.Errorf("%w: %v", ErrTokenParse, v)
}

func rsaKeyError(v any) error {
	return fmt.Errorf("%w: %v", ErrRSAKey, v)
}
