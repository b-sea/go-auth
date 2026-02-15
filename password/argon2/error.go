package argon2

import (
	"errors"
	"fmt"
)

// ErrDecodeHash is raised when a hash cannot be decoded.
var ErrDecodeHash = errors.New("could not decode hash")

func decodeHashError(value any) error {
	return fmt.Errorf("%w: %v", ErrDecodeHash, value)
}
