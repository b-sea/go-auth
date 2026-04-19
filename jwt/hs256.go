package jwt

var _ Signer = (*HS256)(nil)

// HS256 implements an HS256 JWT signer.
type HS256 struct {
	key []byte
}

// NewHS256 creates a new HS256 JWT signer.
func NewHS256(key []byte) *HS256 {
	return &HS256{
		key: key,
	}
}

// Algorithm returns the signing algorithm.
func (s *HS256) Algorithm() string {
	return "HS256"
}

// SignKey returns the sign key.
func (s *HS256) SignKey() any {
	return s.key
}

// VerifyKey returns the verify key.
func (s *HS256) VerifyKey() any {
	return s.key
}
