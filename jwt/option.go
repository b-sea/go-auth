package jwt

import "time"

// Option is a JWT service creation option.
type Option func(s *Service)

// WithTimeout sets the JWT timeout duration.
func WithTimeout(timeout time.Duration) Option {
	return func(s *Service) {
		if timeout <= 0 {
			return
		}

		s.timeout = timeout
	}
}

// WithLeeway sets the JWT leeway duration.
func WithLeeway(leeway time.Duration) Option {
	return func(s *Service) {
		if leeway < 0 {
			return
		}

		s.leeway = leeway
	}
}

// WithCustomTokenID sets a custom function for generating "jti" JWT claims.
func WithCustomTokenID(fn func() string) Option {
	return func(s *Service) {
		s.newTokenID = fn
	}
}

// WithCustomTimestamp sets a custom function for generating timestamps to be used with the "exp" and "iat" JWT claims.
func WithCustomTimestamp(fn func() time.Time) Option {
	return func(s *Service) {
		s.newTimestamp = fn
	}
}
