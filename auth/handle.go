// Package auth implements authentication and authorization http server details.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/b-sea/go-auth/token"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type contextKey string

const (
	authHeader            = "Authorization"
	tokenType             = "Bearer"
	claimsKey  contextKey = "accessClaims"
)

// Authenticator defines functions required for authentication handlers.
type Authenticator interface {
	token.Authenticator

	Endpoint() string
	AuthRequest(request *http.Request, writer http.ResponseWriter) any
}

type handleConfig struct {
	log     zerolog.Logger
	authNs  []Authenticator
	authZ   token.Authorizer
	access  token.Accessor
	refresh token.Refresher
}

// Handle builds auth handlers on the given router.
func Handle(log zerolog.Logger, router *mux.Router, authN Authenticator, access token.Accessor, options ...Option) {
	cfg := &handleConfig{
		log:     log,
		authNs:  []Authenticator{authN},
		authZ:   nil,
		access:  access,
		refresh: nil,
	}

	for _, option := range options {
		option(cfg)
	}

	for _, authN := range cfg.authNs {
		endpoint := fmt.Sprintf("/auth/%s/token", authN.Endpoint())

		cfg.log.Debug().Str("method", http.MethodPost).Str("path", endpoint).Msg("register")
		router.Handle(
			endpoint,
			tokenHandle(authN, cfg.authZ, cfg.access, cfg.refresh),
		).Methods(http.MethodPost)
	}

	if cfg.refresh != nil {
		cfg.log.Debug().Str("method", http.MethodPost).Str("path", "/auth/refresh").Msg("register")
		router.Handle("/auth/refresh", refreshHandle(cfg.authZ, cfg.access, cfg.refresh)).Methods(http.MethodPost)
	}
}

// Middleware ensures a request contains a valid access token, and extracts claims to the request context.
func Middleware(access token.Accessor) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			found, ok := strings.CutPrefix(request.Header.Get(authHeader), tokenType+" ")
			if !ok {
				writeUnauthorized(writer, tokenType)

				return
			}

			claims, err := access.ParseAccessClaims(found)
			if err != nil {
				zerolog.Ctx(request.Context()).Info().Err(err).Msg("invalid token")
				writeUnauthorized(writer, tokenType)

				return
			}

			zerolog.Ctx(request.Context()).Info().Str("subject", claims.Subject()).Msg("token validated")
			next.ServeHTTP(writer, request.WithContext(ToContext(request.Context(), claims)))
		})
	}
}

type authWriter struct {
	header http.Header
	Code   int
	Data   []byte
}

func (w *authWriter) Header() http.Header {
	return w.header
}

func (w *authWriter) WriteHeader(statusCode int) {
	w.Code = statusCode
}

func (w *authWriter) Write(p []byte) (int, error) {
	w.Data = p

	return len(p), nil
}

type tokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ExpiresIn    int    `json:"expiresIn"`
	Type         string `json:"type"`
}

func tokenHandle( //nolint: funlen
	authN Authenticator,
	authZ token.Authorizer,
	access token.Accessor,
	refresh token.Refresher,
) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		start := time.Now()

		hijack := &authWriter{
			header: make(http.Header),
		}

		creds := authN.AuthRequest(request, hijack)
		if hijack.Code >= http.StatusBadRequest {
			for key, values := range hijack.Header() {
				for i := range values {
					writer.Header().Add(key, values[i])
				}
			}

			writer.WriteHeader(hijack.Code)
			_, _ = writer.Write(hijack.Data)

			return
		}

		subject, err := authN.Authenticate(creds)
		if err != nil {
			writeUnauthorized(writer)

			return
		}

		claims := token.NewAccessClaims(subject, []string{})

		if authZ != nil {
			claims, err = authZ.AccessClaims(subject)
			if err != nil {
				writeUnauthorized(writer)

				return
			}
		}

		accessPayload := access.NewAccessToken(claims)

		var refreshToken string

		if refresh != nil {
			refreshToken = refresh.NewRefreshToken(subject).Token
		}

		zerolog.Ctx(request.Context()).Info().
			Dur("duration_ms", time.Since(start)).
			Str("subject", subject).
			Msg("authenticated")

		writer.Header().Add("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(
			tokens{
				AccessToken:  accessPayload.Token,
				RefreshToken: refreshToken,
				Type:         tokenType,
				ExpiresIn:    accessPayload.ExpiresIn,
			},
		)
	}
}

func refreshHandle(authZ token.Authorizer, access token.Accessor, refresh token.Refresher) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		start := time.Now()

		found, ok := strings.CutPrefix(request.Header.Get(authHeader), tokenType+" ")
		if !ok {
			writeUnauthorized(writer, tokenType)

			return
		}

		subject, err := refresh.ParseRefreshSubject(found)
		if err != nil {
			writeUnauthorized(writer, tokenType)

			return
		}

		claims := token.NewAccessClaims(subject, []string{})

		if authZ != nil {
			claims, err = authZ.AccessClaims(subject)
			if err != nil {
				writeUnauthorized(writer)

				return
			}
		}

		accessPayload := access.NewAccessToken(claims)

		zerolog.Ctx(request.Context()).Info().
			Dur("duration_ms", time.Since(start)).
			Str("subject", subject).
			Msg("authenticated")

		writer.Header().Add("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(
			tokens{
				AccessToken: accessPayload.Token,
				Type:        tokenType,
				ExpiresIn:   accessPayload.ExpiresIn,
			},
		)
	}
}

func writeUnauthorized(writer http.ResponseWriter, challenges ...string) {
	if len(challenges) == 0 {
		challenges = append(challenges, "")
	}

	for _, scheme := range challenges {
		writer.Header().Add("WWW-Authenticate", scheme)
	}

	http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// ToContext stores the given claims in the context.
func ToContext(ctx context.Context, claims token.AccessClaims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// FromContext extracts claims from the given context.
// If no claims are found, empty claims are returned.
func FromContext(ctx context.Context) token.AccessClaims {
	claims, ok := ctx.Value(claimsKey).(token.AccessClaims)
	if !ok {
		return token.AccessClaims{}
	}

	return claims
}
