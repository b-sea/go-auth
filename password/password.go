// Package password validates, verifies, and hashes passwords.
package password

import (
	"fmt"
	"unicode"
)

const (
	minLength = 10
	maxLength = 255
)

// Encrypter defines all functions required for encrypting data.
type Encrypter interface {
	// Hash an input string.
	Hash(input string) (string, error)

	// Compare an input string with an hashed string.
	Compare(input string, hash string) (bool, error)
}

// Complexity controls the required characters in a password.
type Complexity struct {
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

// Service implements a standard password managing service.
type Service struct {
	encrypt    Encrypter
	minLength  int
	maxLength  int
	complexity Complexity
}

// NewService creates a new password service.
func NewService(encrypt Encrypter, opts ...Option) *Service {
	service := &Service{
		encrypt:   encrypt,
		minLength: minLength,
		maxLength: maxLength,
		complexity: Complexity{
			RequireUpper:   false,
			RequireLower:   false,
			RequireNumber:  false,
			RequireSpecial: false,
		},
	}

	for _, opt := range opts {
		opt(service)
	}

	return service
}

// Validate checks a given password against any enabled complexity rules.
func (s *Service) Validate(password string) error { //nolint: cyclop
	hasNumber := false
	hasUpper := false
	hasLower := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		default:
		}
	}

	issues := []string{}
	if len(password) < s.minLength {
		issues = append(issues, fmt.Sprintf("password must be at least %d characters", s.minLength))
	}

	if s.complexity.RequireUpper && !hasUpper {
		issues = append(issues, "at least one uppercase character required")
	}

	if s.complexity.RequireLower && !hasLower {
		issues = append(issues, "at least one lowercase character required")
	}

	if s.complexity.RequireNumber && !hasNumber {
		issues = append(issues, "at least one numeric character required")
	}

	if s.complexity.RequireSpecial && !hasSpecial {
		issues = append(issues, "at least one special character required")
	}

	if len(issues) > 0 {
		return ValidationError{
			Reasons: issues,
		}
	}

	return nil
}

// Compare a password to a hashed password.
func (s *Service) Compare(password string, passwordHash string) (bool, error) {
	result, err := s.encrypt.Compare(password, passwordHash)
	if err != nil {
		return false, fmt.Errorf("%w", err)
	}

	return result, nil
}

// Hash the given password.
func (s *Service) Hash(password string) (string, error) {
	runes := []rune(password)
	if len(runes) > s.maxLength {
		password = string(runes[:s.maxLength])
	}

	result, err := s.encrypt.Hash(password)
	if err != nil {
		return "", fmt.Errorf("%w", err)
	}

	return result, nil
}
