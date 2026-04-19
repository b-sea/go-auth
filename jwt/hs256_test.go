package jwt_test

import (
	"testing"

	"github.com/b-sea/go-auth/jwt"
	"github.com/stretchr/testify/assert"
)

func TestHS256(t *testing.T) {
	t.Parallel()

	key := "my_secret_key"

	signer := jwt.NewHS256([]byte(key))
	assert.Equal(t, "HS256", signer.Algorithm())
	assert.IsType(t, []byte{}, signer.VerifyKey())
	assert.IsType(t, []byte{}, signer.SignKey())
}
