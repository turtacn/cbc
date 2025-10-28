package crypto

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeyStatus identifies the status of a key.
type KeyStatus int

const (
	KeyStatusUnknown KeyStatus = iota
	KeyStatusActive
	KeyStatusInactive
)

// Algorithm constants for key types.
const (
	RSA2048 = "RSA-2048"
)

// KeyMetadata holds metadata about a key.
type KeyMetadata struct {
	ID        string
	Algorithm string
	Status    KeyStatus
	CreatedAt time.Time
}

// KeyPair holds the key material.
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
	Meta       KeyMetadata
}

// JWTManager is the backwards-compatible interface for middleware/tests.
type JWTManager interface {
	GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (string, string, error)
	VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error)
}
