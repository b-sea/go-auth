package auth

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	minLength = 10
	maxLength = 255
)

// InvalidPasswordError is raised when a password does not pass validation.
type InvalidPasswordError struct {
	Issues []string `json:"issues"`
}

func (e InvalidPasswordError) Error() string {
	return "invalid password: " + strings.Join(e.Issues, ", ")
}

// EncryptRepo defines all functions required for hashing data.
type EncryptRepo interface {
	Verify(input string, hash string) (bool, error)
	Generate(input string) (string, error)
}

// PasswordOption is a password service creation option.
type PasswordOption func(*PasswordService)

// WithMaxLength sets the maximum password length.
// Defaults to 255.
func WithMaxLength(max int) PasswordOption {
	return func(ps *PasswordService) {
		ps.maxLength = max
	}
}

// WithMinLength sets the minimum password length.
// Defaults to 10.
func WithMinLength(min int) PasswordOption {
	return func(ps *PasswordService) {
		ps.minLength = min
	}
}

// WithUpper requires an upper case character in the password.
func WithUpper(require bool) PasswordOption {
	return func(ps *PasswordService) {
		ps.requireUpper = require
	}
}

// WithLower requires a lower case character in the password.
func WithLower(require bool) PasswordOption {
	return func(ps *PasswordService) {
		ps.requireLower = require
	}
}

// WithSpecial requires a special character in the password.
func WithSpecial(require bool) PasswordOption {
	return func(ps *PasswordService) {
		ps.requireSpecial = require
	}
}

// WithNumber requires a number character in the password.
func WithNumber(require bool) PasswordOption {
	return func(ps *PasswordService) {
		ps.requireNumber = require
	}
}

// PasswordService implements a standard password managing service.
type PasswordService struct {
	encrypt EncryptRepo

	minLength      int
	maxLength      int
	requireUpper   bool
	requireLower   bool
	requireNumber  bool
	requireSpecial bool
}

// NewPasswordService creates a new PasswordService.
func NewPasswordService(encrypt EncryptRepo, opts ...PasswordOption) *PasswordService {
	service := &PasswordService{
		encrypt:   encrypt,
		minLength: 0,
		maxLength: maxLength,
	}

	for _, opt := range opts {
		opt(service)
	}

	return service
}

// ValidatePassword checks a given password against any enabled complexity rules.
func (s *PasswordService) ValidatePassword(password string) error {
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
		return InvalidPasswordError{
			Issues: issues,
		}
	}

	return nil
}

// VerifyPassword compares a password to a hashed password.
func (s *PasswordService) VerifyPassword(password string, passwordHash string) (bool, error) {
	result, err := s.encrypt.Verify(password, passwordHash)
	if err != nil {
		return false, fmt.Errorf("%w", err)
	}

	return result, nil
}

// GeneratePasswordHash encrypts the given password.
func (s *PasswordService) GeneratePasswordHash(password string) (string, error) {
	runes := []rune(password)
	if len(runes) > s.maxLength {
		password = string(runes[:s.maxLength])
	}

	result, err := s.encrypt.Generate(password)
	if err != nil {
		return "", fmt.Errorf("%w", err)
	}

	return result, nil
}
