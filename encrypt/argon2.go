// Package encrypt is responsible for encryption.
package encrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const encodedParamCount = 6

// ErrDecodeHash is raised when a hash cannot be decoded.
var ErrDecodeHash = errors.New("could not decode hash")

func decodeHashError(value interface{}) error {
	return fmt.Errorf("%w: %v", ErrDecodeHash, value)
}

// Argon2Option is a argon2 repo creation option.
type Argon2Option func(*Argon2Repo)

// WithParams sets the argon2 parameters.
// Defaults to
//
//	    Memory:     12
//	    Passes:     1
//		   Threads:    3
//		   SaltLength: 16
//		   KeyLength:  32
func WithParams(params Argon2Params) Argon2Option {
	return func(ar *Argon2Repo) {
		ar.params = params
	}
}

// WithSalt sets the salt generator function.
// Defaults to a randomly generated value.
func WithSalt(salt func(uint32) ([]byte, error)) Argon2Option {
	return func(ar *Argon2Repo) {
		ar.salt = salt
	}
}

// WithPepper sets a pepper value.
func WithPepper(pepper string) Argon2Option {
	return func(ar *Argon2Repo) {
		ar.pepper = pepper
	}
}

// Argon2Params defines all fields for encrypting with Argon2.
type Argon2Params struct {
	Memory     uint32
	Passes     uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

// Argon2Repo implements data hashing with the Argon2 encryption library.
type Argon2Repo struct {
	params Argon2Params
	salt   func(uint32) ([]byte, error)
	pepper string
}

// NewArgon2Repo creates a new Argon2Repo.
func NewArgon2Repo(opts ...Argon2Option) *Argon2Repo {
	repo := &Argon2Repo{
		params: Argon2Params{
			Memory:     12, //nolint: gomnd
			Passes:     1,
			Threads:    3,  //nolint: gomnd
			SaltLength: 16, //nolint: gomnd
			KeyLength:  32, //nolint: gomnd
		},
		salt:   generateRandomBytes,
		pepper: "",
	}

	for _, opt := range opts {
		opt(repo)
	}

	return repo
}

// Verify compares an input string with an encoded hash string.
func (r *Argon2Repo) Verify(input string, encodedHash string) (bool, error) {
	params, salt, hash, err := r.decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey(
		[]byte(r.pepper+input),
		salt,
		params.Passes,
		params.Memory,
		params.Threads,
		params.KeyLength,
	)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// Generate creates an encoded hash string from an input string.
func (r *Argon2Repo) Generate(input string) (string, error) {
	salt, err := r.salt(r.params.SaltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(r.pepper+input),
		salt,
		r.params.Passes,
		r.params.Memory,
		r.params.Threads,
		r.params.KeyLength,
	)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		r.params.Memory,
		r.params.Passes,
		r.params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encodedHash, nil
}

func (r *Argon2Repo) decodeHash(encodedHash string) (*Argon2Params, []byte, []byte, error) {
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

	params := &Argon2Params{}

	_, err = fmt.Sscanf(values[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Passes, &params.Threads)
	if err != nil {
		return nil, nil, nil, decodeHashError(err)
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, decodeHashError(err)
	}

	params.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.Strict().DecodeString(values[5])
	if err != nil {
		return nil, nil, nil, decodeHashError(err)
	}

	params.KeyLength = uint32(len(hash))

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
