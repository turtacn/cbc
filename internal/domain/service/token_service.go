package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/errors"
)

// TokenService defines the core business logic for token operations.
type TokenService interface {
	// IssueTokenPair creates a new pair of access and refresh tokens for a device.
	IssueTokenPair(ctx context.Context, tenant *models.Tenant, device *models.Device) (accessToken, refreshToken *models.Token, err *errors.AppError)

	// RefreshToken validates an old refresh token and issues a new pair of tokens.
	// It implements refresh token rotation.
	RefreshToken(ctx context.Context, oldRefreshTokenString string) (accessToken, refreshToken *models.Token, err *errors.AppError)

	// VerifyToken validates a token string (typically an access token).
	// It checks the signature, expiration, and revocation status.
	VerifyToken(ctx context.Context, tokenString string) (*models.Token, *errors.AppError)

	// RevokeToken marks a specific token (identified by its JTI) as revoked.
	RevokeToken(ctx context.Context, jti string) *errors.AppError
}
//Personal.AI order the ending