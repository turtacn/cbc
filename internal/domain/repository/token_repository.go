package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/errors"
)

// TokenRepository defines the interface for interacting with token storage.
type TokenRepository interface {
	// Save persists a new token to the storage.
	Save(ctx context.Context, token *models.Token) *errors.AppError

	// FindByJTI retrieves a token by its JTI (JWT ID).
	FindByJTI(ctx context.Context, jti string) (*models.Token, *errors.AppError)

	// FindByDeviceID retrieves the latest token for a specific device.
	// This might be useful for limiting one active refresh token per device.
	FindByDeviceID(ctx context.Context, deviceID uuid.UUID, tokenType string) (*models.Token, *errors.AppError)

	// Revoke marks a token as revoked in the storage.
	Revoke(ctx context.Context, jti string, revokedAt time.Time) *errors.AppError

	// DeleteExpired removes tokens that have passed their expiration date.
	// Returns the number of tokens deleted.
	DeleteExpired(ctx context.Context) (int64, *errors.AppError)
}

//Personal.AI order the ending
