package jwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/b-sea/go-auth/jwt"
	"github.com/b-sea/go-auth/token"
	"github.com/stretchr/testify/assert"
)

var _ jwt.Signer = (*Signer)(nil)

type Signer struct {
	AlgorithmResult string
	SignKeyResult   any
	VerifyKeyResult any
}

func (m *Signer) Algorithm() string {
	return m.AlgorithmResult
}

func (m *Signer) SignKey() any {
	return m.SignKeyResult
}

func (m *Signer) VerifyKey() any {
	return m.VerifyKeyResult
}

func TestNewService(t *testing.T) {
	type testCase struct {
		issuer  string
		signer  jwt.Signer
		options []jwt.Option
		err     error
	}

	tests := map[string]testCase{
		"success": {
			issuer: "unit-test",
			signer: &Signer{
				AlgorithmResult: "HS256",
				SignKeyResult:   []byte(`1`),
				VerifyKeyResult: []byte(`1`),
			},
			options: []jwt.Option{},
			err:     nil,
		},
		"no issuer": {
			issuer: "",
			signer: &Signer{
				AlgorithmResult: "HS256",
				SignKeyResult:   []byte(`1`),
				VerifyKeyResult: []byte(`1`),
			},
			options: []jwt.Option{},
			err:     errors.New("token issuer cannot be empty"),
		},
		"bad signer": {
			issuer: "unit-test",
			signer: &Signer{
				AlgorithmResult: "UNKNOWN",
			},
			options: []jwt.Option{},
			err:     errors.New("unknown sign algorithm: UNKNOWN"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := jwt.NewService(test.issuer, test.signer, test.options...)
			if test.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.err.Error())
			}
		})
	}
}

func TestServiceParseAccessClaims(t *testing.T) {
	type testCase struct {
		signer  jwt.Signer
		options []jwt.Option
		token   string
		result  token.AccessClaims
		err     error
	}

	tests := map[string]testCase{
		"success": {
			signer: &Signer{
				AlgorithmResult: "HS256",
				SignKeyResult:   []byte(`1`),
				VerifyKeyResult: []byte(`1`),
			},
			options: []jwt.Option{
				jwt.WithCustomTimestamp(func() time.Time { return time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC) }),
				jwt.WithCustomTokenID(func() string { return "abc" }),
				jwt.WithTimeout(time.Duration(100000 * time.Hour)),
			},
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1bml0LXRlc3QiLCJzdWIiOiJ0ZXN0LXVzZXIiLCJleHAiOjIxMjcyMjU2MDAsIm5iZiI6MTc2NzIyNTYwMCwiaWF0IjoxNzY3MjI1NjAwLCJqdGkiOiJhYmMiLCJ0eXAiOiJBQ0NFU1MiLCJzY3AiOlsicmVhZCJdfQ.INFeisGRv4CNo2Ry4sX--_WM2JZPx2Y6IXVCe4erJrs",
			result: token.NewAccessClaims("test-user", []string{"read"}),
			err:    nil,
		},
		"empty token": {
			signer: &Signer{
				AlgorithmResult: "HS256",
				SignKeyResult:   []byte(`1`),
				VerifyKeyResult: []byte(`1`),
			},
			options: []jwt.Option{
				jwt.WithCustomTimestamp(func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }),
				jwt.WithCustomTokenID(func() string { return "abc" }),
				jwt.WithTimeout(time.Duration(100000 * time.Hour)),
				jwt.WithLeeway(time.Duration(time.Second)),
			},
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.l1wE3dxoVDpxGoLf6PbRCmuC4vLONUmhE9Yky5qySdM",
			err: errors.New(
				"error parsing token: token has invalid claims: " +
					"token is missing required claim: exp claim is required, " +
					"token is missing required claim: nbf claim is required, " +
					"token is missing required claim: iss claim is required, " +
					"token is missing required claim: typ claim is required, " +
					"token is missing required claim: jti claim is required, " +
					"token is missing required claim: sub claim is required",
			),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service, err := jwt.NewService("unit-test", test.signer, test.options...)
			assert.NoError(t, err)

			result, err := service.ParseAccessClaims(test.token)
			assert.Equal(t, test.result, result)
			if test.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.err.Error())
			}
		})
	}
}

func TestServiceNewAccessToken(t *testing.T) {
	type testCase struct {
		signer  jwt.Signer
		options []jwt.Option
		claims  token.AccessClaims
		result  token.Payload
		err     error
	}

	tests := map[string]testCase{
		"success": {
			signer: &Signer{
				AlgorithmResult: "HS256",
				SignKeyResult:   []byte(`1`),
				VerifyKeyResult: []byte(`1`),
			},
			options: []jwt.Option{
				jwt.WithCustomTimestamp(func() time.Time { return time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC) }),
				jwt.WithCustomTokenID(func() string { return "abc" }),
			},
			claims: token.NewAccessClaims("test-user", []string{"read"}),
			result: token.Payload{
				Token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1bml0LXRlc3QiLCJzdWIiOiJ0ZXN0LXVzZXIiLCJleHAiOi02MjEzNTU5NTkwMCwibmJmIjotNjIxMzU1OTY4MDAsImlhdCI6LTYyMTM1NTk2ODAwLCJqdGkiOiJhYmMiLCJ0eXAiOiJBQ0NFU1MiLCJzY3AiOlsicmVhZCJdfQ.oeATjz9uHSohBLrxmzEInwgO4-mcGc3X3JQ-fpNFRag",
				ExpiresIn: 900,
			},
			err: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tkn, err := jwt.NewService(
				"unit-test",
				test.signer,
				test.options...,
			)
			assert.NoError(t, err)

			assert.Equal(t, test.result, tkn.NewAccessToken(test.claims))
		})
	}
}

func TestServiceParseRefreshSubject(t *testing.T) {
	type testCase struct {
		signer  jwt.Signer
		options []jwt.Option
		token   string
		result  string
		err     error
	}

	tests := map[string]testCase{
		"success": {
			signer: &Signer{
				AlgorithmResult: "HS256",
				SignKeyResult:   []byte(`1`),
				VerifyKeyResult: []byte(`1`),
			},
			options: []jwt.Option{
				jwt.WithCustomTimestamp(func() time.Time { return time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC) }),
				jwt.WithCustomTokenID(func() string { return "abc" }),
				jwt.WithTimeout(time.Duration(100000 * time.Hour)),
			},
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1bml0LXRlc3QiLCJzdWIiOiJ0ZXN0LXVzZXIiLCJleHAiOjIxMjcyMjkyMDAsIm5iZiI6MTc2NzIyOTIwMCwiaWF0IjoxNzY3MjI5MjAwLCJqdGkiOiJhYmMiLCJ0eXAiOiJSRUZSRVNIIn0.0kVAzaGhw5JRUL-hED03BBo5HXeBOskuFcxrIEeWR0I",
			result: "test-user",
			err:    nil,
		},
		"empty token": {
			signer: &Signer{
				AlgorithmResult: "HS256",
				SignKeyResult:   []byte(`1`),
				VerifyKeyResult: []byte(`1`),
			},
			options: []jwt.Option{
				jwt.WithCustomTimestamp(func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }),
				jwt.WithCustomTokenID(func() string { return "abc" }),
				jwt.WithTimeout(time.Duration(100000 * time.Hour)),
			},
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.l1wE3dxoVDpxGoLf6PbRCmuC4vLONUmhE9Yky5qySdM",
			err: errors.New(
				"error parsing token: token has invalid claims: " +
					"token is missing required claim: exp claim is required, " +
					"token is missing required claim: nbf claim is required, " +
					"token is missing required claim: iss claim is required, " +
					"token is missing required claim: typ claim is required, " +
					"token is missing required claim: jti claim is required, " +
					"token is missing required claim: sub claim is required",
			),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service, err := jwt.NewService("unit-test", test.signer, test.options...)
			assert.NoError(t, err)

			result, err := service.ParseRefreshSubject(test.token)
			assert.Equal(t, test.result, result)
			if test.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.err.Error())
			}
		})
	}
}

func TestServiceNewRefreshToken(t *testing.T) {
	type testCase struct {
		signer  jwt.Signer
		options []jwt.Option
		subject string
		result  token.Payload
		err     error
	}

	tests := map[string]testCase{
		"success": {
			signer: &Signer{
				AlgorithmResult: "HS256",
				SignKeyResult:   []byte(`1`),
				VerifyKeyResult: []byte(`1`),
			},
			options: []jwt.Option{
				jwt.WithCustomTimestamp(func() time.Time { return time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC) }),
				jwt.WithCustomTokenID(func() string { return "abc" }),
			},
			subject: "test-user",
			result: token.Payload{
				Token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1bml0LXRlc3QiLCJzdWIiOiJ0ZXN0LXVzZXIiLCJleHAiOi02MjEzNTU5NTkwMCwibmJmIjotNjIxMzU1OTY4MDAsImlhdCI6LTYyMTM1NTk2ODAwLCJqdGkiOiJhYmMiLCJ0eXAiOiJSRUZSRVNIIn0.__hs0EQaFnMv6RGoh9omkBhlpJ-sNP6Ac2Rx99HF7jg",
				ExpiresIn: 900,
			},
			err: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tkn, err := jwt.NewService(
				"unit-test",
				test.signer,
				test.options...,
			)
			assert.NoError(t, err)

			assert.Equal(t, test.result, tkn.NewRefreshToken(test.subject))
		})
	}
}
