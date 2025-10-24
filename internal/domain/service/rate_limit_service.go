package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
)

// RateLimitService defines the interface for checking and managing rate limits.
type RateLimitService interface {
	// Allow checks if a request is allowed under the defined rate limits.
	// It supports different scopes (tenant, device, IP).
	Allow(ctx context.Context, scope constants.RateLimitScope, identifier string) (bool, *errors.AppError)

	// ResetLimit manually resets the rate limit counter for a specific identifier.
	ResetLimit(ctx context.Context, scope constants.RateLimitScope, identifier string) *errors.AppError

	// GetCurrentUsage retrieves the current usage for a specific rate limit window.
	// Useful for debugging and monitoring.
	GetCurrentUsage(ctx context.Context, scope constants.RateLimitScope, identifier string) (int, *errors.AppError)
}
//Personal.AI order the ending