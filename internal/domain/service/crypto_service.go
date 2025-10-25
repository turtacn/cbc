package service

import (
	"context"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/errors"
)

// CryptoService defines the interface for cryptographic operations,
// primarily JWT handling and key management.
type CryptoService interface {
	// GenerateJWT creates and signs a new JWT.
	GenerateJWT(ctx context.Context, token *models.Token) (string, *errors.AppError)

	// VerifyJWT parses and validates a JWT string.
	// It returns the token claims if the token is valid.
	VerifyJWT(ctx context.Context, tokenString string, tenantID uuid.UUID) (*jwt.RegisteredClaims, *errors.AppError)

	// GetPublicKey retrieves the current public key for a given tenant.
	// This is used by resource servers to verify token signatures.
	GetPublicKey(ctx context.Context, tenantID uuid.UUID, keyID string) (*rsa.PublicKey, *errors.AppError)

	// GetPrivateKey retrieves the current private key for a given tenant.
	// This is used by the auth service to sign tokens.
	GetPrivateKey(ctx context.Context, tenantID uuid.UUID) (*rsa.PrivateKey, string, *errors.AppError)
}

//Personal.AI order the ending
