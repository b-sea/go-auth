package auth_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/b-sea/go-auth/auth"
	"github.com/b-sea/go-auth/token"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

var _ token.Accessor = (*Accessor)(nil)

type Accessor struct {
	NewAccessTokenResult    token.Payload
	ParseAccessClaimsResult token.AccessClaims
	ParseAccessClaimsErr    error
}

func (m *Accessor) NewAccessToken(token.AccessClaims) token.Payload {
	return m.NewAccessTokenResult
}

func (m *Accessor) ParseAccessClaims(string) (token.AccessClaims, error) {
	return m.ParseAccessClaimsResult, m.ParseAccessClaimsErr
}

var _ token.Refresher = (*Refresher)(nil)

type Refresher struct {
	NewRefreshTokenResult     token.Payload
	ParseRefreshSubjectResult string
	ParseRefreshSubjectErr    error
}

func (m *Refresher) NewRefreshToken(string) token.Payload {
	return m.NewRefreshTokenResult
}

func (m *Refresher) ParseRefreshSubject(string) (string, error) {
	return m.ParseRefreshSubjectResult, m.ParseRefreshSubjectErr
}

var _ auth.Authenticator = (*Authenticator)(nil)

type Authenticator struct {
	EndpointResult          string
	AuthRequestResult       any
	AuthRequestWriterResult func(http.ResponseWriter)
	AuthenticateResult      string
	AuthenticateErr         error
}

func (m *Authenticator) Endpoint() string {
	return m.EndpointResult
}

func (m *Authenticator) AuthRequest(_ *http.Request, w http.ResponseWriter) any {
	if m.AuthRequestWriterResult != nil {
		m.AuthRequestWriterResult(w)
	}

	return m.AuthRequestResult
}

func (m *Authenticator) Authenticate(any) (string, error) {
	return m.AuthenticateResult, m.AuthenticateErr
}

var _ token.Authorizer = (*Authorizer)(nil)

type Authorizer struct {
	AccessClaimsResult token.AccessClaims
	AccessClaimsErr    error
}

func (m Authorizer) AccessClaims(subject string) (token.AccessClaims, error) {
	return m.AccessClaimsResult, m.AccessClaimsErr
}

func TestMiddleware(t *testing.T) {
	type testCase struct {
		access   token.Accessor
		headers  http.Header
		code     int
		response string
	}

	tests := map[string]testCase{
		"success": {
			access: &Accessor{
				ParseAccessClaimsResult: token.NewAccessClaims("test-user", []string{"read"}),
			},
			headers: http.Header{
				"Authorization": []string{"Bearer 123-my-token-456"},
			},
			code:     http.StatusOK,
			response: "",
		},
		"wrong token type": {
			access: &Accessor{},
			headers: http.Header{
				"Authorization": []string{"Custom 123456"},
			},
			code:     http.StatusUnauthorized,
			response: "Unauthorized\n",
		},
		"parse error": {
			access: &Accessor{
				ParseAccessClaimsErr: errors.New("invalid token"),
			},
			headers: http.Header{
				"Authorization": []string{"Bearer some.random.token"},
			},
			code:     http.StatusUnauthorized,
			response: "Unauthorized\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			router := mux.NewRouter()

			auth.Handle(
				router,
				&Authenticator{
					EndpointResult: "mock",
				},
				test.access,
			)

			router.Use(auth.Middleware(test.access))
			router.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

			request, _ := http.NewRequest(http.MethodGet, "/", nil)
			request.Header = test.headers

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			assert.Equal(t, test.code, recorder.Result().StatusCode)
			assert.Equal(t, test.response, recorder.Body.String())
		})
	}
}

func TestTokenHandle(t *testing.T) {
	type testCase struct {
		authN       auth.Authenticator
		access      token.Accessor
		body        []byte
		code        int
		contentType string
		response    string
	}

	tests := map[string]testCase{
		"success": {
			authN: &Authenticator{
				EndpointResult: "mock",
			},
			access: &Accessor{
				NewAccessTokenResult: token.Payload{Token: "123-my-token", ExpiresIn: 33},
			},
			body:        []byte(`"username"`),
			code:        http.StatusOK,
			contentType: "application/json",
			response:    "{\"accessToken\":\"123-my-token\",\"expiresIn\":33,\"type\":\"Bearer\"}\n",
		},
		"unauthorized": {
			authN: &Authenticator{
				EndpointResult:  "mock",
				AuthenticateErr: errors.New("bad creds"),
			},
			access: &Accessor{
				NewAccessTokenResult: token.Payload{Token: "123-my-token", ExpiresIn: 33},
			},
			body:        []byte(`"username"`),
			code:        http.StatusUnauthorized,
			contentType: "text/plain; charset=utf-8",
			response:    "Unauthorized\n",
		},
		"bad request": {
			authN: &Authenticator{
				EndpointResult: "mock",
				AuthRequestWriterResult: func(w http.ResponseWriter) {
					w.Header().Add("Content-Type", "application/json")
					_, _ = w.Write([]byte("\"bad input\"\n"))
					w.WriteHeader(http.StatusBadRequest)
				},
			},
			access: &Accessor{
				NewAccessTokenResult: token.Payload{Token: "123-my-token", ExpiresIn: 33},
			},
			body:        []byte(`some random input`),
			code:        http.StatusBadRequest,
			contentType: "application/json",
			response:    "\"bad input\"\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			router := mux.NewRouter()
			auth.Handle(router, test.authN, test.access)

			request, _ := http.NewRequest(
				http.MethodPost,
				fmt.Sprintf("/auth/%s/token", test.authN.Endpoint()),
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

func TestRefreshHandle(t *testing.T) {
	type testCase struct {
		refresh     token.Refresher
		access      token.Accessor
		header      http.Header
		code        int
		contentType string
		response    string
	}

	tests := map[string]testCase{
		"success": {
			access: &Accessor{
				NewAccessTokenResult: token.Payload{Token: "123-my-token", ExpiresIn: 33},
			},
			refresh:     &Refresher{},
			header:      http.Header{"Authorization": {"Bearer 456-refresh-token"}},
			code:        http.StatusOK,
			contentType: "application/json",
			response:    "{\"accessToken\":\"123-my-token\",\"expiresIn\":33,\"type\":\"Bearer\"}\n",
		},
		"unauthorized": {
			access: &Accessor{},
			refresh: &Refresher{
				ParseRefreshSubjectErr: errors.New("uh oh!"),
			},
			header:      http.Header{"Authorization": {"Bearer 456-refresh-token"}},
			code:        http.StatusUnauthorized,
			contentType: "text/plain; charset=utf-8",
			response:    "Unauthorized\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			router := mux.NewRouter()
			auth.Handle(
				router,
				&Authenticator{},
				test.access,
				auth.WithRefreshToken(test.refresh),
				auth.WithAuthZ(&Authorizer{}),
			)

			request, _ := http.NewRequest(http.MethodPost, "/auth/refresh", nil)
			request.Header = test.header

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			assert.Equal(t, test.code, recorder.Result().StatusCode)
			assert.Equal(t, test.contentType, recorder.Header().Get("Content-Type"))
			assert.Equal(t, test.response, recorder.Body.String())
		})
	}
}

func TestToFromContext(t *testing.T) {
	t.Parallel()

	claims := token.NewAccessClaims("test-user", []string{"read", "write"})
	ctx := auth.ToContext(context.Background(), claims)
	found := auth.FromContext(ctx)
	assert.Equal(t, claims, found)

	empty := auth.FromContext(context.Background())
	assert.Equal(t, token.AccessClaims{}, empty)
}
