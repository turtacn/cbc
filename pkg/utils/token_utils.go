package utils

import "github.com/google/uuid"

// ExtractJTIFromToken extracts the JTI claim from a JWT.
// This is a placeholder implementation.
func ExtractJTIFromToken(token string) (string, error) {
	return uuid.NewString(), nil
}
