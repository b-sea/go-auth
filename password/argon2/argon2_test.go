package argon2_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/b-sea/go-auth/password/argon2"
	"github.com/stretchr/testify/assert"
)

func TestArgon2Compare(t *testing.T) {
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
			err:   errors.New("could not decode hash: the encoded hash is not the correct format"),
		},
		"mismatch format": {
			input: "password",
			hash:  "$argon2id$a=19$m=12,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$FnsyBo1AJop51mFbEOAVn0/ApOnA/ldKEqf7+SfwNa0",
			err:   errors.New("could not decode hash: input does not match format"),
		},
		"incompatible version": {
			input: "password",
			hash:  "$argon2id$v=1$m=12,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$FnsyBo1AJop51mFbEOAVn0/ApOnA/ldKEqf7+SfwNa0",
			err:   errors.New("could not decode hash: incompatible version of argon2"),
		},
		"bad params": {
			input: "password",
			hash:  "$argon2id$v=19$m=12,a=69,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$FnsyBo1AJop51mFbEOAVn0/ApOnA/ldKEqf7+SfwNa0",
			err:   errors.New("could not decode hash: input does not match format"),
		},
		"bad salt": {
			input: "password",
			hash:  "$argon2id$v=19$m=12,t=1,p=3$different-salt$FnsyBo1AJop51mFbEOAVn0/ApOnA/ldKEqf7+SfwNa0",
			err:   errors.New("could not decode hash: illegal base64 data at input byte 9"),
		},
		"bad hash": {
			input: "password",
			hash:  "$argon2id$v=19$m=12,t=1,p=3$YWFhYWFhYWFhYWFhYWFhYQ$different-hash",
			err:   errors.New("could not decode hash: illegal base64 data at input byte 9"),
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		argon2 := argon2.New(argon2.WithPepper(testCase.pepper))

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := argon2.Compare(testCase.input, testCase.hash)

			assert.Equal(t, testCase.result, result)
			if testCase.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, testCase.err.Error())
			}
		})
	}
}

func TestArgon2Hash(t *testing.T) {
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
			salt:  func(u uint32) ([]byte, error) { return nil, errors.New("uh oh") },
			input: "password",
			err:   errors.New("uh oh"),
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			argon2 := argon2.New(
				argon2.WithSalt(testCase.salt),
				argon2.WithSaltLength(16),
				argon2.WithPepper(testCase.pepper),
				argon2.WithParams(
					argon2.Params{
						Memory:    12,
						Passes:    1,
						Threads:   3,
						KeyLength: 32,
					},
				),
			)
			result, err := argon2.Hash(testCase.input)

			assert.Equal(t, testCase.result, result)
			if testCase.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, testCase.err.Error())
			}
		})
	}
}
