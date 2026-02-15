package password

// Option is a password service creation option.
type Option func(s *Service)

// WithMaxLength sets the maximum password length.
func WithMaxLength(length int) Option {
	return func(s *Service) {
		if length <= 0 {
			return
		}

		s.maxLength = length
	}
}

// WithMinLength sets the minimum password length.
func WithMinLength(length int) Option {
	return func(s *Service) {
		if length <= 0 {
			return
		}

		s.minLength = length
	}
}

// WithComplexity sets the required password complexity.
func WithComplexity(complexity Complexity) Option {
	return func(s *Service) {
		s.complexity = complexity
	}
}
