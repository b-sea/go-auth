package password_test

import (
	"errors"
	"testing"

	"github.com/b-sea/go-auth/password"
	"github.com/stretchr/testify/assert"
)

var _ password.Encrypter = (*Encrypt)(nil)

type Encrypt struct {
	CompareResult bool
	CompareErr    error
	HashResult    string
	HashErr       error
}

func (r *Encrypt) Compare(string, string) (bool, error) {
	return r.CompareResult, r.CompareErr
}

func (r *Encrypt) Hash(string) (string, error) {
	return r.HashResult, r.HashErr
}

func TestPasswordValidate(t *testing.T) {
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
			err: password.ValidationError{
				Reasons: []string{"at least one uppercase character required"},
			},
		},
		"missing lowercase": {
			password: "P@SSW0RD",
			err: password.ValidationError{
				Reasons: []string{"at least one lowercase character required"},
			},
		},
		"missing number": {
			password: "P@ssword",
			err: password.ValidationError{
				Reasons: []string{"at least one numeric character required"},
			},
		},
		"missing special": {
			password: "Passw0rd",
			err: password.ValidationError{
				Reasons: []string{"at least one special character required"},
			},
		},
		"too short": {
			password: "Pwd0!",
			err: password.ValidationError{
				Reasons: []string{"password must be at least 8 characters"},
			},
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		pwd := password.NewService(
			&Encrypt{},
			password.WithMinLength(8),
			password.WithMaxLength(100),
			password.WithComplexity(
				password.Complexity{
					RequireUpper:   true,
					RequireLower:   true,
					RequireNumber:  true,
					RequireSpecial: true,
				},
			),
		)

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			err := pwd.Validate(testCase.password)
			if testCase.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, testCase.err.Error())
			}
		})
	}
}

func TestPasswordCompare(t *testing.T) {
	type test struct {
		encrypt  password.Encrypter
		password string
		hash     string
		result   bool
		err      error
	}

	testCases := map[string]test{
		"matched": {
			encrypt: &Encrypt{
				CompareResult: true,
			},
			password: "password",
			hash:     "1a2b3c4d",
			result:   true,
		},
		"no match": {
			encrypt: &Encrypt{
				CompareResult: false,
			},
			password: "password",
			hash:     "1a2b3c4d",
			result:   false,
		},
		"error": {
			encrypt: &Encrypt{
				CompareErr: errors.New("some hash error"),
			},
			password: "password",
			hash:     "1a2b3c4d",
			err:      errors.New("some hash error"),
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		pwd := password.NewService(testCase.encrypt)

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := pwd.Compare(testCase.password, testCase.hash)

			assert.Equal(t, testCase.result, result)
			if testCase.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, testCase.err.Error())
			}
		})
	}
}

func TestPasswordServiceGenerateHash(t *testing.T) {
	type test struct {
		encrypt   password.Encrypter
		maxLength int
		password  string
		result    string
		err       error
	}

	testCases := map[string]test{
		"success": {
			encrypt: &Encrypt{
				HashResult: "1a2b3c4d",
			},
			password: "password",
			result:   "1a2b3c4d",
		},
		"really long password": {
			encrypt: &Encrypt{
				HashResult: "1a2b3c4d",
			},
			password: "this is a really long password, how are you today? i'm doing fine, thanks for asking.",
			result:   "1a2b3c4d",
		},
		"truncated length": {
			encrypt: &Encrypt{
				HashResult: "1a2b3c4d",
			},
			maxLength: 20,
			password:  "blah blah blah blah blah blah blah blah blah blah",
			result:    "1a2b3c4d",
		},
		"error": {
			encrypt: &Encrypt{
				HashErr: errors.New("some hash error"),
			},
			password: "password",
			err:      errors.New("some hash error"),
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		pwd := password.NewService(testCase.encrypt, password.WithMaxLength(testCase.maxLength))

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := pwd.Hash(testCase.password)

			assert.Equal(t, testCase.result, result)
			if testCase.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, testCase.err.Error())
			}
		})
	}
}
