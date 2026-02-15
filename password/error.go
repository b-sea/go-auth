package password

import (
	"strings"
)

// ValidationError is raised when a password does not pass validation.
type ValidationError struct {
	Reasons []string `json:"reasons"`
}

func (e ValidationError) Error() string {
	return "validation error: " + strings.Join(e.Reasons, ", ")
}
