// Package password validates, verifies, and hashes passwords.
package password

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/b-sea/go-auth/password/encrypt"
)

const (
	minLength = 10
	maxLength = 255
)

// InvalidError is raised when a password does not pass validation.
type InvalidError struct {
	Issues []string `json:"issues"`
}

func (e InvalidError) Error() string {
	return "invalid password: " + strings.Join(e.Issues, ", ")
}

// Option is a password service creation option.
type Option func(*Service)

// WithMaxLength sets the maximum password length.
// Defaults to 255.
func WithMaxLength(max int) Option {
	return func(ps *Service) {
		ps.maxLength = max
	}
}

// WithMinLength sets the minimum password length.
// Defaults to 10.
func WithMinLength(min int) Option {
	return func(ps *Service) {
		ps.minLength = min
	}
}

// WithUpper requires an upper case character in the password.
func WithUpper(require bool) Option {
	return func(ps *Service) {
		ps.requireUpper = require
	}
}

// WithLower requires a lower case character in the password.
func WithLower(require bool) Option {
	return func(ps *Service) {
		ps.requireLower = require
	}
}

// WithSpecial requires a special character in the password.
func WithSpecial(require bool) Option {
	return func(ps *Service) {
		ps.requireSpecial = require
	}
}

// WithNumber requires a number character in the password.
func WithNumber(require bool) Option {
	return func(ps *Service) {
		ps.requireNumber = require
	}
}

// Service implements a standard password managing service.
type Service struct {
	repo encrypt.Repository

	minLength      int
	maxLength      int
	requireUpper   bool
	requireLower   bool
	requireNumber  bool
	requireSpecial bool
}

// NewService creates a new Service.
func NewService(repo encrypt.Repository, opts ...Option) *Service {
	service := &Service{
		repo:      repo,
		minLength: 0,
		maxLength: maxLength,
	}

	for _, opt := range opts {
		opt(service)
	}

	return service
}

// ValidatePassword checks a given password against any enabled complexity rules.
func (s *Service) ValidatePassword(password string) error {
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

	if s.requireUpper && !hasUpper {
		issues = append(issues, "at least one uppercase character required")
	}

	if s.requireLower && !hasLower {
		issues = append(issues, "at least one lowercase character required")
	}

	if s.requireNumber && !hasNumber {
		issues = append(issues, "at least one numeric character required")
	}

	if s.requireSpecial && !hasSpecial {
		issues = append(issues, "at least one special character required")
	}

	if len(issues) > 0 {
		return InvalidError{
			Issues: issues,
		}
	}

	return nil
}

// Verify compares a password to a hashed password.
func (s *Service) Verify(password string, passwordHash string) (bool, error) {
	result, err := s.repo.Verify(password, passwordHash)
	if err != nil {
		return false, fmt.Errorf("%w", err)
	}

	return result, nil
}

// GenerateHash encrypts the given password.
func (s *Service) GenerateHash(password string) (string, error) {
	runes := []rune(password)
	if len(runes) > s.maxLength {
		password = string(runes[:s.maxLength])
	}

	result, err := s.repo.Generate(password)
	if err != nil {
		return "", fmt.Errorf("%w", err)
	}

	return result, nil
}
