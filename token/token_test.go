package token_test

import (
	"testing"

	"github.com/b-sea/go-auth/token"
	"github.com/stretchr/testify/assert"
)

func TestAccessClaims(t *testing.T) {
	t.Parallel()

	claims := token.NewAccessClaims("test-user", []string{"read", "WrItE"})
	assert.Equal(t, "test-user", claims.Subject())
	assert.Equal(t, []string{"read", "WrItE"}, claims.Scopes())
	assert.True(t, claims.HasScope("read"))
	assert.True(t, claims.HasScope("write"))
	assert.False(t, claims.HasScope("admin"))
}
