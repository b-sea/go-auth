// Package encrypt is responsible for password encryption.
package encrypt

// Repository defines all functions required for hashing data.
type Repository interface {
	Verify(input string, hash string) (bool, error)
	Generate(input string) (string, error)
}
