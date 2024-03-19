package auth_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/b-sea/go-auth"
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
		signMethod string
		err        error
	}

	testCases := map[string]test{
		"success": {
			publicKey:  []byte(publicKey),
			privateKey: []byte(privateKey),
			signMethod: "RS256",
		},
		"unknown sign method": {
			publicKey:  []byte(publicKey),
			privateKey: []byte(privateKey),
			signMethod: "SOMETHING_ELSE",
			err:        auth.ErrRSAKey,
		},
		"bad public key": {
			publicKey:  []byte("-----BAD PUBLIC KEY-----"),
			privateKey: []byte(privateKey),
			signMethod: "RS256",
			err:        auth.ErrRSAKey,
		},
		"bad private key": {
			publicKey:  []byte(publicKey),
			privateKey: []byte("-----BAD PRIVATE KEY-----"),
			signMethod: "RS256",
			err:        auth.ErrRSAKey,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			config := auth.TokenConfig{
				PublicKey:      testCase.publicKey,
				PrivateKey:     testCase.privateKey,
				SignMethod:     testCase.signMethod,
				Issuer:         "unit-tests",
				AccessTimeout:  time.Hour,
				RefreshTimeout: time.Hour,
			}

			_, err := auth.NewTokenService(config)

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

	auth.Timestamp = func() time.Time {
		return time.Date(2009, 11, 10, 12, 30, 0, 0, time.Local)
	}

	type test struct {
		sub      string
		issuer   string
		audience string
		result   string
		err      error
	}

	testCases := map[string]test{
		"success": {
			sub:      "user-id",
			issuer:   "unit-tests",
			audience: "special-service",
			result:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1bml0LXRlc3RzIiwic3ViIjoidXNlci1pZCIsImF1ZCI6WyJhY2Nlc3MiLCJzcGVjaWFsLXNlcnZpY2UiXSwiZXhwIjoxMjU3ODc3ODAwLCJpYXQiOjEyNTc4NzQyMDAsImp0aSI6IjEyMzQtbXktaWQtNTY3OCJ9.VNDEbYubYKBOspkQCIq76MtuEjfuS2ztUGskix7WfcR-rN8J-WPHnFtMDzsggC9fe9uF0AQyWoLtti45v7n4JSU01vgITtMhMIKANc837eJT3RBcIzI8Qc7_fSKXzO30xiQWAm8acUFu4RsUl4syEgarcHSxI-9qBzoKMYOISv6XIwdSgDKXxJ7Szs3rFYzPhA3ZDMu-JwMmTNKgoQGtX6RfvubPm5QUGHiP9FcHlIyTBXxF2mOk0_tWNGEZVTVy07hSPVz9ni1HQiliMvipTDDaMxsAZNbfAu_enfnhjdl5t-sH77Oio-OXBiF5i_N82_hFqvJ9BPw8fpPwbqlkEA",
		},
		"no issuer": {
			sub:      "user-id",
			audience: "special-service",
			result:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLWlkIiwiYXVkIjpbImFjY2VzcyIsInNwZWNpYWwtc2VydmljZSJdLCJleHAiOjEyNTc4Nzc4MDAsImlhdCI6MTI1Nzg3NDIwMCwianRpIjoiMTIzNC1teS1pZC01Njc4In0.O_2UWotrwh9thG7fvAPFcFVT2mJ6odTWa6nyikmf0PBMAJ85vLS8Gw_tjC075D_F8iKT7IQ6G3JKX8IEQdNIn4akhVjEZh5rOLF1kMFxBfMfBx9ZRsR8MeW5xudvLbUafsRfI2kIoCSvc1X3xe2hB0kF4x16R74L1iUOJdqhVkOOEzx3BYbJvpuX7gbqlQ-dkGNPk1Dk-evdtMD9kuiT8TaoS5anpX7G51mMK8I8zcCOjkW7J46bU9NA9n6XKCNmWKaNA1u91U5f32OYfj7ja8X975mLdM2HgYm-TKjjYvgU9h-vdPpKXXyLMI3GXnsyn-_vhvbCCFr8I6XLuFBeHQ",
		},
		"no audience": {
			sub:    "user-id",
			issuer: "unit-tests",
			result: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1bml0LXRlc3RzIiwic3ViIjoidXNlci1pZCIsImF1ZCI6WyJhY2Nlc3MiXSwiZXhwIjoxMjU3ODc3ODAwLCJpYXQiOjEyNTc4NzQyMDAsImp0aSI6IjEyMzQtbXktaWQtNTY3OCJ9.DVURPqPA2Djq9_uZJyhBXS1iG5gaPAq4g2sJRhloRsQEVhYOucem3jhJitbk-zFaXFEXqP6rx067ux8TgxPr74CkjwoaQV4zJSGbFlNY0TZQBbQdhsvlxj4RssyKUdn6qSHWD7O67kyUZBLHmYtpUdrKT0ctAiiBsWmddbapmzUyDng750SFifPzCvRLs2qhDvOQ5Wc--yBL7sttakymwnOyzYISpdWbLcjuJFPhJrtjcqjeYsSnG-VS48Pi0h4GroyvTEpM6nrNuG6Uq3v9NT6qmbVSFi4arRlkmYaXnfbS5K18GNSUENh-srtgdDc2vv7SGFi0RLt-A5H2wpVnVw",
		},
		"no subject": {
			issuer:   "unit-tests",
			audience: "special-service",
			err:      auth.ErrJWTClaim,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		config := auth.TokenConfig{
			PublicKey:      []byte(publicKey),
			PrivateKey:     []byte(privateKey),
			SignMethod:     "RS256",
			Issuer:         testCase.issuer,
			Audience:       testCase.audience,
			AccessTimeout:  time.Hour,
			RefreshTimeout: time.Hour,
			IDGenerator: func() string {
				return "1234-my-id-5678"
			},
		}

		tokenService, err := auth.NewTokenService(config)
		if err == nil {
			assert.NoError(t, err, "no error expected during service creation")
		}

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := tokenService.GenerateAccessToken(testCase.sub)

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

	auth.Timestamp = func() time.Time {
		return time.Date(2009, 11, 10, 12, 30, 0, 0, time.Local)
	}

	type test struct {
		sub      string
		issuer   string
		audience string
		result   string
		err      error
	}

	testCases := map[string]test{
		"success": {
			sub:      "user-id",
			issuer:   "unit-tests",
			audience: "special-service",
			result:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1bml0LXRlc3RzIiwic3ViIjoidXNlci1pZCIsImF1ZCI6WyJyZWZyZXNoIiwic3BlY2lhbC1zZXJ2aWNlIl0sImV4cCI6MTI1Nzg3NzgwMCwiaWF0IjoxMjU3ODc0MjAwLCJqdGkiOiIxMjM0LW15LWlkLTU2NzgifQ.u1-UnorN3qO3XUlK6gE7o0bL0mn-cbctP3Vmy9jRNTccks6Qaj4OjGRCF-AxYvLtliqcqFgkA7q9Q2KVSx_cqcjpXiSRZMtsvDAv5O6Evl-VjYYYE81JxfP84OgQ2Ga6BI-b0Coaoq73iOjmLmd-6HxuIiTUZiamGmho8RjVSoEYD0dZqqU5SKtG5AtuEADJB57Y6WM021VTxZsic31JC81aQp0RibMPi4x5-foazS6rStgjeZhk70kWP7LbUsVOw0PxdA8ULJxAp8hMHSqt4H7TaMS6CBEz2sJMbpOJ6KIa1pqznnj_vAHqurqq0vDNJ8Bff-4BIRNMygU9Hn9Lmw",
		},
		"no issuer": {
			sub:      "user-id",
			audience: "special-service",
			result:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLWlkIiwiYXVkIjpbInJlZnJlc2giLCJzcGVjaWFsLXNlcnZpY2UiXSwiZXhwIjoxMjU3ODc3ODAwLCJpYXQiOjEyNTc4NzQyMDAsImp0aSI6IjEyMzQtbXktaWQtNTY3OCJ9.LrahHdJJQh8DbfyDHRVf98asSci4n8QtxSrstle7GzAPKin0v_TI8L6hmkdMEbt8sPKMG5uJHZazoLxFulLgU2J3rmVJPkAGVrbyCl4K8q27jZwHkuKxfhEAGMO9yZo50MotxgEu9SJjp7dJv36wiB9DYo4ygSn5Y4XtsQ6hqE_v7f-9ECSZah1ZL4-MOK1PrbyKI4Pa6tkJI88MphqYaOsTNvlogG73BLS23deLxvXs-p0PYxp46MJnj_IUa_U75VdpbGUFtKEDa_dD3hXqbaV7DuUnDh7CZycxHI-u6aZUU0c0W3C2NK92k5E1lyL885glCbySVxOlA2QgNgA_jg",
		},
		"no audience": {
			sub:    "user-id",
			issuer: "unit-tests",
			result: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1bml0LXRlc3RzIiwic3ViIjoidXNlci1pZCIsImF1ZCI6WyJyZWZyZXNoIl0sImV4cCI6MTI1Nzg3NzgwMCwiaWF0IjoxMjU3ODc0MjAwLCJqdGkiOiIxMjM0LW15LWlkLTU2NzgifQ.k74fMG-nPD62agG_oFM4etraCIIJbPBj-wg6PvyfWT4oK0ZVnQxH17_96B1nZtiX5WQtiDob-dbSAJVw49w5y7gmixPuaM0wpfZBkw8ZtiQrV5HdGO7tSV5yVIrfbqStXXU-gyd5sBnob3ibuMLw3bFQklOZjMn5-xnwDhTo1aeF08f4F4zzSE-Les1eu0Mp5b-wm3mZxgjeIsECRnmRyFZxbEX8Z40mOz61WYnbQj01qhxfOQ3Ji2iDRGGDU_9ZoL61zOROVxaGiNa_2kCCzBwruyQke0wMLNmZg0OiZb5Wnidxgswg2JJpsX186I9z5ab1uFeMu3XM1FvzCASrkg",
		},
		"no subject": {
			issuer:   "unit-tests",
			audience: "special-service",
			err:      auth.ErrJWTClaim,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		config := auth.TokenConfig{
			PublicKey:      []byte(publicKey),
			PrivateKey:     []byte(privateKey),
			SignMethod:     "RS256",
			Issuer:         testCase.issuer,
			Audience:       testCase.audience,
			AccessTimeout:  time.Hour,
			RefreshTimeout: time.Hour,
			IDGenerator: func() string {
				return "1234-my-id-5678"
			},
		}

		tokenService, err := auth.NewTokenService(config)
		if err == nil {
			assert.NoError(t, err, "no error expected during service creation")
		}

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, err := tokenService.GenerateRefreshToken(testCase.sub)

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

		config := auth.TokenConfig{
			PublicKey:      []byte(publicKey),
			PrivateKey:     []byte(privateKey),
			SignMethod:     "RS256",
			Issuer:         "unit-tests",
			Audience:       "special-service",
			AccessTimeout:  time.Hour,
			RefreshTimeout: time.Hour,
		}

		tokenService, err := auth.NewTokenService(config)
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

		config := auth.TokenConfig{
			PublicKey:      []byte(publicKey),
			PrivateKey:     []byte(privateKey),
			SignMethod:     "RS256",
			Issuer:         "unit-tests",
			Audience:       "special-service",
			AccessTimeout:  time.Hour,
			RefreshTimeout: time.Hour,
		}

		tokenService, err := auth.NewTokenService(config)
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

func TestFromHeader(t *testing.T) {
	t.Parallel()

	type test struct {
		header http.Header
		result string
		ok     bool
	}

	testCases := map[string]test{
		"success": {
			header: http.Header{
				"Authorization": []string{"Bearer --my-token--"},
			},
			result: "--my-token--",
			ok:     true,
		},
		"no header": {
			header: http.Header{},
			ok:     false,
		},
		"multiple headers": {
			header: http.Header{
				"Authorization": []string{
					"Bearer --my-token--",
					"Bearer another-token!",
				},
			},
			ok: false,
		},
		"non bearer": {
			header: http.Header{
				"Authorization": []string{"Basic user:pwd(but in base64)"},
			},
			ok: false,
		},
	}

	for name, testCase := range testCases {
		name, testCase := name, testCase

		config := auth.TokenConfig{
			PublicKey:      []byte(publicKey),
			PrivateKey:     []byte(privateKey),
			SignMethod:     "RS256",
			Issuer:         "unit-tests",
			AccessTimeout:  time.Hour,
			RefreshTimeout: time.Hour,
		}

		tokenService, err := auth.NewTokenService(config)
		if err == nil {
			assert.NoError(t, err, "no error expected during service creation")
		}

		t.Run(name, func(s *testing.T) {
			s.Parallel()

			result, ok := tokenService.FromHeader(testCase.header)

			assert.Equal(t, testCase.result, result, "different results")
			assert.Equal(t, testCase.ok, ok, "different ok")
		})
	}
}
