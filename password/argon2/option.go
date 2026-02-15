package argon2

// Option is a argon2 creation option.
type Option func(a *Argon2)

// WithSaltLength sets the salt length.
func WithSaltLength(length uint32) Option {
	return func(a *Argon2) {
		a.saltLength = length
	}
}

// WithSalt sets the salt generator function.
func WithSalt(salt func(uint32) ([]byte, error)) Option {
	return func(a *Argon2) {
		a.salt = salt
	}
}

// WithPepper sets a pepper value.
func WithPepper(pepper string) Option {
	return func(a *Argon2) {
		a.pepper = pepper
	}
}

// WithParams sets the argon2 parameters.
func WithParams(params Params) Option {
	return func(a *Argon2) {
		a.params = params
	}
}
