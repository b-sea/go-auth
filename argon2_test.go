package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/b-sea/go-auth"
	"github.com/stretchr/testify/assert"
)

var errSalt = errors.New("salt failed")

func TestArgon2RepoVerify(t *testing.T) {
	t.Parallel()

	type test struct {
		input  string
		pepper string
		hash   string
		result bool
		err    error
	}

	testCases := map[string]test{
		"matched": {
			input:  "password",
			hash:   "$argon2id$v=19$m=12,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$FnsyBo1AJop51mFbEOAVn0/ApOnA/ldKEqf7+SfwNa0",
			result: true,
		},
		"no match": {
			pepper: "spicy",
			input:  "password",
			hash:   "$argon2id$v=19$m=12,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$FnsyBo1AJop51mFbEOAVn0/ApOnA/ldKEqf7+SfwNa0",
			result: false,
		},
		"incorrect hash format": {
			input: "password",
			hash:  "hashashashashashash",
			err:   auth.ErrDecodeHash,
		},
		"missing version param": {
			input: "password",
			hash:  "$argon2id$a=19$m=12,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$FnsyBo1AJop51mFbEOAVn0/ApOnA/ldKEqf7+SfwNa0",
			err:   auth.ErrDecodeHash,
		},
		"mismatch version": {
			input: "password",
			hash:  "$argon2id$v=1$m=12,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$FnsyBo1AJop51mFbEOAVn0/ApOnA/ldKEqf7+SfwNa0",
			err:   auth.ErrDecodeHash,
		},
		"bad params": {
			input: "password",
			hash:  "$argon2id$v=19$m=12,a=69,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$FnsyBo1AJop51mFbEOAVn0/ApOnA/ldKEqf7+SfwNa0",
			err:   auth.ErrDecodeHash,
		},
		"bad salt": {
			input: "password",
			hash:  "$argon2id$v=19$m=12,t=1,p=3$different-salt$FnsyBo1AJop51mFbEOAVn0/ApOnA/ldKEqf7+SfwNa0",
			err:   auth.ErrDecodeHash,
		},
		"bad hash": {
			input: "password",
			hash:  "$argon2id$v=19$m=12,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$different-hash",
			err:   auth.ErrDecodeHash,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		argon2 := auth.NewArgon2Repo(auth.WithPepper(testCase.pepper))

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := argon2.Verify(testCase.input, testCase.hash)

			assert.Equal(t, testCase.result, result, "different results")
			if testCase.err == nil {
				assert.NoError(t, err, "no error expected")
			} else {
				assert.ErrorIs(t, err, testCase.err, "different errors")
			}
		})
	}
}

func TestArgon2RepoGenerate(t *testing.T) {
	t.Parallel()

	type test struct {
		salt   func(u uint32) ([]byte, error)
		pepper string
		input  string
		result string
		err    error
	}

	testCases := map[string]test{
		"success": {
			salt:   func(u uint32) ([]byte, error) { return []byte(strings.Repeat("a", int(u))), nil },
			pepper: "spicy",
			input:  "password",
			result: "$argon2id$v=19$m=12,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$slk6r+gCnh2FBDjmRVbs/5rrhu3SGjszZNW9ZqSS9Z0",
		},
		"salt error": {
			salt:  func(u uint32) ([]byte, error) { return nil, errSalt },
			input: "password",
			err:   errSalt,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			argon2 := auth.NewArgon2Repo(auth.WithSalt(testCase.salt), auth.WithPepper(testCase.pepper))
			result, err := argon2.Generate(testCase.input)

			assert.Equal(t, testCase.result, result, "different results")
			if testCase.err == nil {
				assert.NoError(t, err, "no error expected")
			} else {
				assert.ErrorIs(t, err, testCase.err, "different errors")
			}
		})
	}
}
