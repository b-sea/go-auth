// Package argon2 implements encryption with Argon2.
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/b-sea/go-auth/password"
	"golang.org/x/crypto/argon2"
)

const (
	encodedParamCount = 6
	defaultSaltLength = 16
	defaultMemory     = uint32(64 * 1024)
	defaultPasses     = 2
	defaultThreads    = 4
	defaultKeyLength  = 32
)

// Params defines all fields for encrypting with Argon2.
type Params struct {
	Memory    uint32
	Passes    uint32
	Threads   uint8
	KeyLength uint32
}

var _ password.Encrypter = (*Argon2)(nil)

// Argon2 implements data hashing with the  encryption library.
type Argon2 struct {
	params     Params
	saltLength uint32
	salt       func(uint32) ([]byte, error)
	pepper     string
}

// New creates a new Argon2.
func New(opts ...Option) *Argon2 {
	encrypt := &Argon2{
		params: Params{
			Memory:    defaultMemory,
			Passes:    defaultPasses,
			Threads:   defaultThreads,
			KeyLength: defaultKeyLength,
		},
		saltLength: defaultSaltLength,
		salt:       generateRandomBytes,
		pepper:     "",
	}

	for _, opt := range opts {
		opt(encrypt)
	}

	return encrypt
}

// Compare an input string with an hashed string.
func (a *Argon2) Compare(input string, hashed string) (bool, error) {
	params, salt, hash, err := a.decodeHash(hashed)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey(
		[]byte(a.pepper+input),
		salt,
		params.Passes,
		params.Memory,
		params.Threads,
		params.KeyLength,
	)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// Hash an input string.
func (a *Argon2) Hash(input string) (string, error) {
	salt, err := a.salt(a.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(a.pepper+input),
		salt,
		a.params.Passes,
		a.params.Memory,
		a.params.Threads,
		a.params.KeyLength,
	)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.params.Memory,
		a.params.Passes,
		a.params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encodedHash, nil
}

func (a *Argon2) decodeHash(encodedHash string) (*Params, []byte, []byte, error) {
	values := strings.Split(encodedHash, "$")
	if len(values) != encodedParamCount {
		return nil, nil, nil, decodeHashError("the encoded hash is not the correct format")
	}

	var version int

	_, err := fmt.Sscanf(values[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, decodeHashError(err)
	}

	if version != argon2.Version {
		return nil, nil, nil, decodeHashError("incompatible version of argon2")
	}

	params := &Params{}

	_, err = fmt.Sscanf(values[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Passes, &params.Threads)
	if err != nil {
		return nil, nil, nil, decodeHashError(err)
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, decodeHashError(err)
	}

	a.saltLength = uint32(len(salt)) //nolint: gosec

	hash, err := base64.RawStdEncoding.Strict().DecodeString(values[5])
	if err != nil {
		return nil, nil, nil, decodeHashError(err)
	}

	params.KeyLength = uint32(len(hash)) //nolint: gosec

	return params, salt, hash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	bytes := make([]byte, n)

	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return bytes, nil
}
