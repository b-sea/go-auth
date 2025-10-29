package token_test

import (
	"testing"
	"time"

	"github.com/b-sea/go-auth/token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const (
	publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvOOIdRVKAfmyx2pfdN+i
i5ZgO1t3M/uJIfH8viEAWlIIpuRnC0gh1bb1n8ErdeSC2SBvAocLOhrtdZ3aXgAX
+mNvuR5gqRhBdZgPLQXKYqyEH1E0fwecOlg8lLA38g6Rjrw8E2FoQGiw1PebQYmU
eav2VdyZYebwUPH8wxNTqld5iadEZGtXruMBnUlc7CvHr8uavW4hXEGrEt07lYp+
eM+YtlSKzK8EBOBeN7AAz6C0EYYQisWbtB7Xp2qBViau2PAQqKWTdPNR/a0Aq6Bl
iXthJ0h7+uKQiiKGf0p8iJDlPJXbmcj7nGmCkFDgYWQ1eJSBeu8uEtoG8ecGuBmC
RwIDAQAB
-----END PUBLIC KEY-----`

	privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvOOIdRVKAfmyx2pfdN+ii5ZgO1t3M/uJIfH8viEAWlIIpuRn
C0gh1bb1n8ErdeSC2SBvAocLOhrtdZ3aXgAX+mNvuR5gqRhBdZgPLQXKYqyEH1E0
fwecOlg8lLA38g6Rjrw8E2FoQGiw1PebQYmUeav2VdyZYebwUPH8wxNTqld5iadE
ZGtXruMBnUlc7CvHr8uavW4hXEGrEt07lYp+eM+YtlSKzK8EBOBeN7AAz6C0EYYQ
isWbtB7Xp2qBViau2PAQqKWTdPNR/a0Aq6BliXthJ0h7+uKQiiKGf0p8iJDlPJXb
mcj7nGmCkFDgYWQ1eJSBeu8uEtoG8ecGuBmCRwIDAQABAoIBACvB0gS9j81xWNcV
b1OV0wPfLB/UCoNCS/xPIKuy3XAO/O4cjzpv1Va68Z+2kijXbPB7sPu26QTm5AeR
L9sCzos0qdcKkH3bnp5tQWa+pqnBKUJP/4dF7g0eD7qqL+ulMFcOiCQ9NndlSUGs
soy2IG0nRwOQ/P9PDnDR/in6ujEFd/nu9hFYxp87GpNQnG73T9/M/b6CGtRcolqf
JC5EuGpY0kA+HEQ/U9xvh2SRPjxaLMGXwsRRaefy+d+eIvVmuuWLhsTzrBqpewQR
K7zD+JQf3l3m/kI60riPCumfKj89RTXD6VnS1U5ssyIVt5URvroPXsTMvAoSUSEO
oSZBSMECgYEA+OQZ9FWYZosSCglaxREXRoPzTOWchdig8OblwGOrCHaN5jL5fzII
S4Shgk0jVLUlOQqOrVf7bdlHrulCW7sjUSRBCIqUbkevxE6RLD9I+rBiYfdeLoHv
uRDQNKKlOu/QgH5Hc5MyH0k50KUJ7pHofK/1GeijiiEYViE6cKAuLbcCgYEAwkix
kPAe7EiUiWTd52sNgm8cKivcpX0YKoT5J2Z3pYIVgjPCtGvQtJfLl8IR3n6AUXMC
gqllAL4gV/JT8eFmk9QS4jQU1kpXUjxo5ItfYyhGPxCHYxGqwdVb1sHvSG+VHizN
KBbXWxtFhaBCoiysqLNXUnUQpImtiYDaafejT/ECgYA3O+fGoXhAyXwnXgwWz8Qq
kf3cgthJm9mbnKJAH95E8oprG8TixWex2q09DYFZuxmXnxAqx+u0ZRPTbVCcqtsb
lsAX9SkbkC0hk44EE8dOWvZ6ZzsvdwaMO375L18bxTywR1X0ACaPauC5vOaHWzoM
8b+jEE26yb1s39LoS6Pz4QKBgAR1Zp3M5OjHQaFljzIgYs77fcn597ZUiJlxM8aT
s2s48QVr6qv5TXDXivSQn5hbjtZPrV8SRB8gPd3G0eZbJd9+nnBSgafpTNe2SzHz
gNzlr7cCyhib7y9Dljf3e2ZOKT3oCU1COO7+UTof02elXtEATKC3zwn3nuPo8Ro9
dKIBAoGAGWQ8HaMMvZmao6UddYnnbVXV591oXDqzB6DRt4Jrkb7q8rnG0jdAGzY3
zod3zdGwky8r/mR2pffh/1AJCYTcJjKz2LnMZ4JyRnM6GD+K2EyiEAtF/9UivVuT
P2rsDJJHCRKrYIW9y9sxbzwX8OLyCKi1rD58T/gBC31+4ioWiuI=
-----END RSA PRIVATE KEY-----`

	badToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.shoZ2n7XQh60-jp-qBbQ7wCZF3SqxccLvnJNu79LahE9DDc4G9ZIUnoIFicpgWxwN9_jfF60VE_uBxD3f0LXmm7-lU-z1S8Z8GqLjgRsCdxooP_VGm03afe4ong6SfIDHgqUjJ_mvMg2YoYHfBx18-yt0Ru7MRDRhPjiJ_TJQpduHtBTtFGZnLa1cK5RIy2X38SMlJWDcFRh7ygT6xmYot29j3Megc5KagJI1fGYRYhWwMaQqvHTcqhgiPpBLflzXu5FZA5D6jpsKCHooxywKOZcM9WIuvoG7rMGZYpH_bqvuFuaJqinPB-Dx9415lWwmUgF8NwIkD6RaL1vKEoOFg"
)

func TestTokenService(t *testing.T) {
	t.Parallel()

	type test struct {
		publicKey  []byte
		privateKey []byte
		err        error
	}

	testCases := map[string]test{
		"success": {
			publicKey:  []byte(publicKey),
			privateKey: []byte(privateKey),
		},
		"bad public key": {
			publicKey:  []byte("-----BAD PUBLIC KEY-----"),
			privateKey: []byte(privateKey),
			err:        token.ErrRSAKey,
		},
		"bad private key": {
			publicKey:  []byte(publicKey),
			privateKey: []byte("-----BAD PRIVATE KEY-----"),
			err:        token.ErrRSAKey,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			_, err := token.NewService(
				testCase.publicKey,
				testCase.privateKey,
				token.WithIssuer("unit-tests"),
				token.WithAccessTimeout(time.Hour),
				token.WithRefreshTimeout(time.Hour),
			)

			if testCase.err == nil {
				assert.NoError(t, err, "no error expected")
			} else {
				assert.ErrorIs(t, err, testCase.err, "different errors")
			}
		})
	}
}

func TestTokenServiceGenerateAccessToken(t *testing.T) {
	t.Parallel()

	token.Timestamp = func() time.Time {
		return time.Date(2009, 11, 10, 12, 30, 0, 0, time.Local)
	}

	type test struct {
		sub       string
		issuer    string
		audiences []string
		result    string
		err       error
	}

	testCases := map[string]test{
		"success": {
			sub:       "user-id",
			issuer:    "unit-tests",
			audiences: []string{"special-service"},
			result:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1bml0LXRlc3RzIiwic3ViIjoidXNlci1pZCIsImF1ZCI6WyJzcGVjaWFsLXNlcnZpY2UiLCJhY2Nlc3MiXSwiZXhwIjoxMjU3ODc3ODAwLCJpYXQiOjEyNTc4NzQyMDAsImp0aSI6IjEyMzQtbXktaWQtNTY3OCJ9.QcqmtVPpeUAZF_YpgHHQI0vrz72M75yBHBRgJQOFmL_EDl1KrGUksbnBRmbn8zrb0X-jZ7fNAZZ7tBFtyBRIuMpFX8OvlhEwAHU0KXCm2NwXujvG6SNZsRf0wKE8M2AyIChqUtTgtM6Pn4H0ChEoRjUKLPf5V4eg_U9TSgYp9Dojg5b0N9XU4S9NAH9JpRAMe1HXxMMkBrB4ETT0-7NT3LanblHdu2-B0f6yGk5BQNTWv-e4B1RH90aDDnYlqaO44psNK1s6W8rA4vg8txL86aBgHLpQVV3bzi8A62c-vuMi85vsyJ2hX1gg4Mk_jMkwPeW0D3Zu51D7etvGQi6WgA",
		},
		"no issuer": {
			sub:       "user-id",
			audiences: []string{},
			result:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLWlkIiwiYXVkIjpbImFjY2VzcyJdLCJleHAiOjEyNTc4Nzc4MDAsImlhdCI6MTI1Nzg3NDIwMCwianRpIjoiMTIzNC1teS1pZC01Njc4In0.jjpfxE4Uzgc1L-IQ_-OzVnPV6Ew_PWT51rMWCFEmAbFwsZSGQafpaUVzrR6luB-ZeL05lQoEn4fcJucHmM2Q2KFHUAiy5Dm9dSAKaLyorgjVQtEkY_qMEhqsLUXOVFaSPvJsKHirt5I53Xz1t_a-8iTy5eonDEQHs6n4nETOXJCGvnpqcEx3pxV9bi4nMOOAkJ_jg_4A1Ve9r2puOkxRODTB2DOi0gopCIWT4lB7W_fTg8T8P80AWLqOv07Yh5jsV8IdtN_1TbjJgr5b96v_bRTe6n48adLzecDXgHSxVEtFCNc39SWpRfJruN3H1aThu8hJJ5JKzLOyB8JTCqm4Yw",
		},
		"no subject": {
			issuer:    "unit-tests",
			audiences: []string{},
			err:       token.ErrJWTClaim,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		tokenService, err := token.NewService(
			[]byte(publicKey),
			[]byte(privateKey),
			token.WithIssuer(testCase.issuer),
			token.WithAccessTimeout(time.Hour),
			token.WithRefreshTimeout(time.Hour),
			token.WithIDGenerator(func() string { return "1234-my-id-5678" }),
		)
		if err == nil {
			assert.NoError(t, err, "no error expected during service creation")
		}

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := tokenService.GenerateAccessToken(testCase.sub, testCase.audiences...)

			assert.Equal(t, testCase.result, result, "different results")
			if testCase.err == nil {
				assert.NoError(t, err, "no error expected")
			} else {
				assert.ErrorIs(t, err, testCase.err, "different errors")
			}
		})
	}
}

func TestTokenServiceGenerateRefreshToken(t *testing.T) {
	t.Parallel()

	token.Timestamp = func() time.Time {
		return time.Date(2009, 11, 10, 12, 30, 0, 0, time.Local)
	}

	type test struct {
		sub       string
		issuer    string
		audiences []string
		result    string
		err       error
	}

	testCases := map[string]test{
		"success": {
			sub:       "user-id",
			issuer:    "unit-tests",
			audiences: []string{"special-service"},
			result:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1bml0LXRlc3RzIiwic3ViIjoidXNlci1pZCIsImF1ZCI6WyJzcGVjaWFsLXNlcnZpY2UiLCJyZWZyZXNoIl0sImV4cCI6MTI1Nzg3NzgwMCwiaWF0IjoxMjU3ODc0MjAwLCJqdGkiOiIxMjM0LW15LWlkLTU2NzgifQ.U9Lwsv-ArOuxii9ZwBM419hEukcv72zOLG_jMNMG6h7g5iqQaD4FehYgR645eaejtWT_TXcaZSkSM_MvcyKnYXJtLYERSpgIC8Ew5JvjiFg4GV9t5IQ48xhEnuRHpDv5r67sf5MxS43zvL3Lt1HDfhTiG6eEYhUhn6NfHv_J9c4afS2yUOH3l-RzKGG1h2L22LIsH0QOq1omxuLe8jIwolO1QwqlEUohyH4wRC2lJrZeljzzsbXvsj1PbwvVPuCFMml0mJcJo0z2jtCqr4p0XyvEaVmXzXb9WCvNmpRTarsyuOlI_j6mqRXfsfzKRped1aTBiyOdqV9v2g4yMKxR1w",
		},
		"no issuer": {
			sub:       "user-id",
			audiences: []string{},
			result:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLWlkIiwiYXVkIjpbInJlZnJlc2giXSwiZXhwIjoxMjU3ODc3ODAwLCJpYXQiOjEyNTc4NzQyMDAsImp0aSI6IjEyMzQtbXktaWQtNTY3OCJ9.Tzeyah0AhGJQ2bSS5A7UOSBvazWMJbF_eAr1KjXoWlcV2ux3qa5Xr4cRizj1ld6PyGODfwk-T9b0mMrSkvEs9-5MzdcnJewnMFK11yCI3EVJR-ObRr1hRrEpNr8pOMu-MvLKNMvmIjDcbOlZoYdlZRmpSbq3Gu6jXsy3jElAyrHbvI9YGZ9PtUgL2YoEpkguHE6f7p3oRYu0M7iJUJn30JzX249YeGQm9SH17sRb5Uq83EeCTgNlMhGdf4Nl_JqbGkxgKD-_O9YnQem5thb4RZPEoD26hE62u6jnAG-cOvviFcrfhDO1B_w2o9b9DAVN68xUTRfIKm8di-qKBCCsbg",
		},
		"no subject": {
			issuer:    "unit-tests",
			audiences: []string{},
			err:       token.ErrJWTClaim,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		tokenService, err := token.NewService(
			[]byte(publicKey),
			[]byte(privateKey),
			token.WithIssuer(testCase.issuer),
			token.WithAccessTimeout(time.Hour),
			token.WithRefreshTimeout(time.Hour),
			token.WithIDGenerator(func() string { return "1234-my-id-5678" }),
		)
		if err == nil {
			assert.NoError(t, err, "no error expected during service creation")
		}

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := tokenService.GenerateRefreshToken(testCase.sub, testCase.audiences...)

			assert.Equal(t, testCase.result, result, "different results")
			if testCase.err == nil {
				assert.NoError(t, err, "no error expected")
			} else {
				assert.ErrorIs(t, err, testCase.err, "different errors")
			}
		})
	}
}

func TestTokenServiceParseAccessToken(t *testing.T) {
	t.Parallel()

	type test struct {
		token  string
		result *jwt.Token
		err    error
	}

	validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxMjM0LW15LWlkLTU2NzgiLCJzdWIiOiJ1c2VyLWlkIiwiYXVkIjpbImFjY2VzcyIsInNwZWNpYWwtc2VydmljZSJdLCJpc3MiOiJ1bml0LXRlc3RzIiwiaWF0IjoxMjU3ODc0MjAwLCJleHAiOjEwNDgxMjQ2MjM2fQ.Xi5pxkb9e51IGpN8J5OLfy8MqYzGoY5LfutMsGZWZ7nDqTEJN0UN4ChKCWdWXNBhWnn4lDCBDDzUR6p-j4lh0BxeY25l0aJK_hhnI_HkVUZWUiqJmGKiQ4D6I3uOulYCh-Q8k3KcjmsaP6zMmUolNdCdQQ8HDtwytJybEOK-WyhIqeOWe_kNaUFnPi_sMb_M-RvsEJQI6Yxic9Dq5wcSYAuiFCkAjRfAR_8-TCTLnlL_c53-QoDb05JkB17hCWGczoeeFp6W2tXTM-ezcP50lsq_Qyw5UVDW6xsSdY2gOmaSwnK8-GS3vSsqoDrHjlEp1H0HjtDna1TN1kVTloGx-g"

	testCases := map[string]test{
		"success": {
			token: validToken,
			result: &jwt.Token{
				Raw:    validToken,
				Method: jwt.SigningMethodRS256,
				Header: map[string]interface{}{
					"typ": "JWT",
					"alg": jwt.SigningMethodRS256.Alg(),
				},
				Claims: &jwt.RegisteredClaims{
					ID:        "1234-my-id-5678",
					Issuer:    "unit-tests",
					Audience:  []string{"access", "special-service"},
					Subject:   "user-id",
					ExpiresAt: jwt.NewNumericDate(time.Unix(int64(10481246236), 0)),
					IssuedAt:  jwt.NewNumericDate(time.Unix(int64(1257874200), 0)),
				},
				Valid:     true,
				Signature: []byte("^.i\xc6F\xfd{\x9dH\x1a\x93|'\x93\x8b\x7f/\f\xa9\x8cơ\x8eK~\xebL\xb0fVg\xb9é1\t7E\r\xe0(J\tgV\\\xd0aZy\xf8\x940\x81\f<\xd4G\xaa~\x8f\x89a\xd0\x1c^cneѢJ\xfe\x18g#\xf1\xe4UFVR*\x89\x98b\xa2C\x80\xfa#{\x8e\xbaV\x02\x87\xe4<\x93r\x9c\x8ek\x1a?\xac̙J%5НA\x0f\a\x0e\xdc2\xb4\x9c\x9b\x10\xe2\xbe[(H\xa9\xe3\x96{\xf9\riAg>/\xec1\xbf\xcc\xf9\x1b\xec\x10\x94\b\xe9\x8cbs\xd0\xea\xe7\a\x12`\v\xa2\x14)\x00\x8d\x17\xc0G\xff>L$˞R\xffs\x9d\xfeB\x80\xdbӒd\a^\xe1\ta\x9c·\x9e\x16\x9e\x96\xda\xd5\xd33\xe7\xb3p\xfet\x96ʿC,9QP\xd6\xeb\x1b\x12u\x8d\xa0:f\x92\xc2r\xbc\xf8d\xb7\xbd+*\xa0:ǎQ)\xd4}\a\x8e\xd0\xe7kT\xcd\xd6ES\x96\x81\xb1\xfa"),
			},
		},
		"bad token": {
			token: badToken,
			err:   jwt.ErrTokenInvalidClaims,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		tokenService, err := token.NewService(
			[]byte(publicKey),
			[]byte(privateKey),
			token.WithIssuer("unit-tests"),
			token.WithAccessTimeout(time.Hour),
			token.WithRefreshTimeout(time.Hour),
			token.WithIDGenerator(func() string { return "1234-my-id-5678" }),
		)
		if err == nil {
			assert.NoError(t, err, "no error expected during service creation")
		}

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := tokenService.ParseAccessToken(testCase.token)

			assert.Equal(t, testCase.result, result, "different results")
			if testCase.err == nil {
				assert.NoError(t, err, "no error expected")
			} else {
				assert.ErrorIs(t, err, testCase.err, "different errors")
			}
		})
	}
}

func TestTokenServiceParseRefreshToken(t *testing.T) {
	t.Parallel()

	type test struct {
		token  string
		result *jwt.Token
		err    error
	}

	validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxMjM0LW15LWlkLTU2NzgiLCJzdWIiOiJ1c2VyLWlkIiwiYXVkIjpbInJlZnJlc2giLCJzcGVjaWFsLXNlcnZpY2UiXSwiaXNzIjoidW5pdC10ZXN0cyIsImlhdCI6MTI1Nzg3NDIwMCwiZXhwIjoxMDQ4MTI0NjIzNn0.mz1HdpKtbsFdy9_CJ1ArZxx73VCzDYaLwFgzUxrF77Dpp7sS4CqV05LDgk2U0pcR5mQnd_4Z6UZJ_6bjGg3jMdu6-R5vaPbod7ScRpEcPre5YDDAtADkoHiqDb-HWEHbV2uj8u7f8ns6nIr_L7fkF7z5gsqy245Sifnh2xYXU35lzoKw-Bs6wpSR8gRLnHJXA2psIDIN4M-4nnk08aAW2uVRRaLvIzNvvrritBzXBLrz4KX3hM-fMFHrpT9FfaWD_q1Acxw6Op0gKhvzlL7MuxPVrT5ZZseZQCSKpcc86BtontYkW2E43_v0FYPK8j5AS8f2kEwpxvNrZ0ka05w1dA"

	testCases := map[string]test{
		"success": {
			token: validToken,
			result: &jwt.Token{
				Raw:    validToken,
				Method: jwt.SigningMethodRS256,
				Header: map[string]interface{}{
					"typ": "JWT",
					"alg": jwt.SigningMethodRS256.Alg(),
				},
				Claims: &jwt.RegisteredClaims{
					ID:        "1234-my-id-5678",
					Issuer:    "unit-tests",
					Audience:  []string{"refresh", "special-service"},
					Subject:   "user-id",
					ExpiresAt: jwt.NewNumericDate(time.Unix(int64(10481246236), 0)),
					IssuedAt:  jwt.NewNumericDate(time.Unix(int64(1257874200), 0)),
				},
				Valid:     true,
				Signature: []byte("\x9b=Gv\x92\xadn\xc1]\xcb\xdf\xc2'P+g\x1c{\xddP\xb3\r\x86\x8b\xc0X3S\x1a\xc5\xef\xb0駻\x12\xe0*\x95ӒÂM\x94җ\x11\xe6d'w\xfe\x19\xe9FI\xff\xa6\xe3\x1a\r\xe31ۺ\xf9\x1eoh\xf6\xe8w\xb4\x9cF\x91\x1c>\xb7\xb9`0\xc0\xb4\x00\xe4\xa0x\xaa\r\xbf\x87XA\xdbWk\xa3\xf2\xee\xdf\xf2{:\x9c\x8a\xff/\xb7\xe4\x17\xbc\xf9\x82ʲێR\x89\xf9\xe1\xdb\x16\x17S~e\u0382\xb0\xf8\x1b:\u0094\x91\xf2\x04K\x9crW\x03jl 2\r\xe0ϸ\x9ey4\xf1\xa0\x16\xda\xe5QE\xa2\xef#3o\xbe\xba\xe2\xb4\x1c\xd7\x04\xba\xf3\xe0\xa5\xf7\x84ϟ0Q\xeb\xa5?E}\xa5\x83\xfe\xad@s\x1c::\x9d *\x1b\xf3\x94\xbe̻\x13խ>YfǙ@$\x8a\xa5\xc7<\xe8\x1bh\x9e\xd6$[a8\xdf\xfb\xf4\x15\x83\xca\xf2>@K\xc7\xf6\x90L)\xc6\xf3kgI\x1aӜ5t"),
			},
		},
		"bad token": {
			token: badToken,
			err:   jwt.ErrTokenInvalidClaims,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		tokenService, err := token.NewService(
			[]byte(publicKey),
			[]byte(privateKey),
			token.WithIssuer("unit-tests"),
			token.WithAccessTimeout(time.Hour),
			token.WithRefreshTimeout(time.Hour),
			token.WithIDGenerator(func() string { return "1234-my-id-5678" }),
		)
		if err == nil {
			assert.NoError(t, err, "no error expected during service creation")
		}

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := tokenService.ParseRefreshToken(testCase.token)

			assert.Equal(t, testCase.result, result, "different results")
			if testCase.err == nil {
				assert.NoError(t, err, "no error expected")
			} else {
				assert.ErrorIs(t, err, testCase.err, "different errors")
			}
		})
	}
}
