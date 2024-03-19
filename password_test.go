package auth_test

import (
	"errors"
	"testing"

	"github.com/b-sea/go-auth"
	"github.com/stretchr/testify/assert"
)

type MockEncryptRepo struct {
	VerifyResult   bool
	VerifyErr      error
	GenerateResult string
	GenerateErr    error
}

func (r *MockEncryptRepo) Verify(_ string, _ string) (bool, error) {
	return r.VerifyResult, r.VerifyErr
}

func (r *MockEncryptRepo) Generate(_ string) (string, error) {
	return r.GenerateResult, r.GenerateErr
}

func TestPasswordServiceValidatePassword(t *testing.T) {
	t.Parallel()

	type test struct {
		password string
		err      error
	}

	testCases := map[string]test{
		"success": {
			password: "P@ssw0rd",
		},
		"missing uppercase": {
			password: "p@ssw0rd",
			err: auth.InvalidPasswordError{
				Issues: []string{"at least one uppercase character required"},
			},
		},
		"missing lowercase": {
			password: "P@SSW0RD",
			err: auth.InvalidPasswordError{
				Issues: []string{"at least one lowercase character required"},
			},
		},
		"missing number": {
			password: "P@ssword",
			err: auth.InvalidPasswordError{
				Issues: []string{"at least one numeric character required"},
			},
		},
		"missing special": {
			password: "Passw0rd",
			err: auth.InvalidPasswordError{
				Issues: []string{"at least one special character required"},
			},
		},
		"too short": {
			password: "Pwd0!",
			err: auth.InvalidPasswordError{
				Issues: []string{"password must be at least 8 characters"},
			},
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		pwdService := auth.NewPasswordService(
			&MockEncryptRepo{},
			auth.WithMinLength(8),
			auth.WithMaxLength(100),
			auth.WithUpper(true),
			auth.WithLower(true),
			auth.WithNumber(true),
			auth.WithSpecial(true),
		)

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			err := pwdService.ValidatePassword(testCase.password)
			if testCase.err == nil {
				assert.NoError(t, err, "no error expected")
			} else {
				assert.EqualError(t, err, testCase.err.Error(), "different errors")
			}
		})
	}
}

func TestPasswordServiceVerifyPassword(t *testing.T) {
	t.Parallel()

	type test struct {
		encryptRepo auth.EncryptRepo
		password    string
		hash        string
		result      bool
		err         error
	}

	testCases := map[string]test{
		"matched": {
			encryptRepo: &MockEncryptRepo{
				VerifyResult: true,
			},
			password: "password",
			hash:     "1a2b3c4d",
			result:   true,
		},
		"no match": {
			encryptRepo: &MockEncryptRepo{
				VerifyResult: false,
			},
			password: "password",
			hash:     "1a2b3c4d",
			result:   false,
		},
		"error": {
			encryptRepo: &MockEncryptRepo{
				VerifyErr: errors.New("some hash error"),
			},
			password: "password",
			hash:     "1a2b3c4d",
			err:      errors.New("some hash error"),
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		pwdService := auth.NewPasswordService(testCase.encryptRepo)

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := pwdService.VerifyPassword(testCase.password, testCase.hash)

			assert.Equal(t, testCase.result, result, "different results")
			if testCase.err == nil {
				assert.NoError(t, err, "no error expected")
			} else {
				assert.ErrorAs(t, err, &testCase.err, "different errors")
			}
		})
	}
}

func TestPasswordServiceGeneratePasswordHash(t *testing.T) {
	t.Parallel()

	type test struct {
		encryptRepo auth.EncryptRepo
		maxLength   int
		password    string
		result      string
		err         error
	}

	testCases := map[string]test{
		"success": {
			encryptRepo: &MockEncryptRepo{
				GenerateResult: "1a2b3c4d",
			},
			password: "password",
			result:   "1a2b3c4d",
		},
		"really long password": {
			encryptRepo: &MockEncryptRepo{
				GenerateResult: "1a2b3c4d",
			},
			password: "this is a really long password, how are you today? i'm doing fine, thanks for asking.",
			result:   "1a2b3c4d",
		},
		"truncated length": {
			encryptRepo: &MockEncryptRepo{
				GenerateResult: "1a2b3c4d",
			},
			maxLength: 20,
			password:  "blah blah blah blah blah blah blah blah blah blah",
			result:    "1a2b3c4d",
		},
		"error": {
			encryptRepo: &MockEncryptRepo{
				GenerateErr: errors.New("some hash error"),
			},
			password: "password",
			err:      errors.New("some hash error"),
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		pwdService := auth.NewPasswordService(testCase.encryptRepo, auth.WithMaxLength(testCase.maxLength))

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := pwdService.GeneratePasswordHash(testCase.password)

			assert.Equal(t, testCase.result, result, "different results")
			if testCase.err == nil {
				assert.NoError(t, err, "no error expected")
			} else {
				assert.ErrorAs(t, err, &testCase.err, "different errors")
			}
		})
	}
}
