package jwt_test

import (
	"crypto/rsa"
	"os"
	"testing"

	"github.com/b-sea/go-auth/jwt"
	"github.com/stretchr/testify/assert"
)

func TestRS256(t *testing.T) {
	t.Parallel()

	publicKey, err := os.ReadFile("./test/rs256.pub")
	assert.NoError(t, err)

	privateKey, err := os.ReadFile("./test/rs256.key")
	assert.NoError(t, err)

	signer, err := jwt.NewRS256(publicKey, privateKey)
	assert.NoError(t, err)
	assert.Equal(t, "RS256", signer.Algorithm())
	assert.IsType(t, &rsa.PublicKey{}, signer.VerifyKey())
	assert.IsType(t, &rsa.PrivateKey{}, signer.SignKey())

	_, err = jwt.NewRS256([]byte(`bad`), privateKey)
	assert.EqualError(t, err, "rsa key error: invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")

	_, err = jwt.NewRS256(publicKey, []byte(`bad`))
	assert.EqualError(t, err, "rsa key error: invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
}
