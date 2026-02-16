package auth_test

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/b-sea/go-auth/auth"
	"github.com/b-sea/go-auth/token"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestWithAuthZ(t *testing.T) {
	type testCase struct {
		authZ       token.Authorizer
		body        []byte
		code        int
		contentType string
		response    string
	}

	tests := map[string]testCase{
		"success": {
			authZ:       &Authorizer{},
			body:        []byte(`"username"`),
			code:        http.StatusOK,
			contentType: "application/json",
			response:    "{\"accessToken\":\"123-my-token\",\"expiresIn\":33,\"type\":\"Bearer\"}\n",
		},
		"authZ error": {
			authZ: &Authorizer{
				AccessClaimsErr: errors.New("uh oh"),
			},
			body:        []byte(`"username"`),
			code:        http.StatusUnauthorized,
			contentType: "text/plain; charset=utf-8",
			response:    "Unauthorized\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			authN := &Authenticator{
				EndpointResult: "mock",
			}

			router := mux.NewRouter()
			auth.Handle(
				zerolog.New(zerolog.Nop()),
				router,
				authN,
				&Accessor{
					NewAccessTokenResult: token.Payload{Token: "123-my-token", ExpiresIn: 33},
				},
				auth.WithAuthZ(test.authZ),
				auth.WithAuthZ(test.authZ),
			)

			request, _ := http.NewRequest(
				http.MethodPost,
				fmt.Sprintf("/auth/%s/token", authN.Endpoint()),
				bytes.NewBuffer(test.body),
			)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			assert.Equal(t, test.code, recorder.Result().StatusCode)
			assert.Equal(t, test.contentType, recorder.Header().Get("Content-Type"))
			assert.Equal(t, test.response, recorder.Body.String())
		})
	}
}

func TestWithRefreshToken(t *testing.T) {
	type testCase struct {
		refresh     token.Refresher
		body        []byte
		code        int
		contentType string
		response    string
	}

	tests := map[string]testCase{
		"success": {
			refresh: &Refresher{
				NewRefreshTokenResult: token.Payload{Token: "456-refresh-token", ExpiresIn: 99},
			},
			body:        []byte(`"username"`),
			code:        http.StatusOK,
			contentType: "application/json",
			response:    "{\"accessToken\":\"123-my-token\",\"refreshToken\":\"456-refresh-token\",\"expiresIn\":33,\"type\":\"Bearer\"}\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			authN := &Authenticator{
				EndpointResult: "mock",
			}

			router := mux.NewRouter()
			auth.Handle(
				zerolog.New(zerolog.Nop()),
				router,
				authN,
				&Accessor{
					NewAccessTokenResult: token.Payload{Token: "123-my-token", ExpiresIn: 33},
				},
				auth.WithRefreshToken(test.refresh),
			)

			request, _ := http.NewRequest(
				http.MethodPost,
				fmt.Sprintf("/auth/%s/token", authN.Endpoint()),
				bytes.NewBuffer(test.body),
			)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			assert.Equal(t, test.code, recorder.Result().StatusCode)
			assert.Equal(t, test.contentType, recorder.Header().Get("Content-Type"))
			assert.Equal(t, test.response, recorder.Body.String())

			request, _ = http.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer([]byte(``)))

			recorder2 := httptest.NewRecorder()
			router.ServeHTTP(recorder2, request)

			assert.Equal(t, http.StatusUnauthorized, recorder2.Result().StatusCode)
		})
	}
}

func TestWithAddlAuthN(t *testing.T) {
	t.Parallel()

	authN1 := &Authenticator{
		EndpointResult: "mock",
	}
	authN2 := &Authenticator{
		EndpointResult: "another",
	}

	router := mux.NewRouter()
	auth.Handle(
		zerolog.New(zerolog.Nop()),
		router,
		authN1,
		&Accessor{
			NewAccessTokenResult: token.Payload{Token: "123-my-token", ExpiresIn: 33},
		},
		auth.WithAddlAuthN(authN2),
	)

	request, _ := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/auth/%s/token", authN1.Endpoint()),
		bytes.NewBuffer([]byte(``)),
	)
	recorder1 := httptest.NewRecorder()
	router.ServeHTTP(recorder1, request)
	assert.Equal(t, http.StatusOK, recorder1.Result().StatusCode)

	request, _ = http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/auth/%s/token", authN2.Endpoint()),
		bytes.NewBuffer([]byte(``)),
	)

	recorder2 := httptest.NewRecorder()
	router.ServeHTTP(recorder2, request)

	assert.Equal(t, http.StatusOK, recorder2.Result().StatusCode)

}
