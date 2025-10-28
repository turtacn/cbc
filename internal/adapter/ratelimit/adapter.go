package ratelimitadapter

import (
	"context"
	"time"

	domain "github.com/turtacn/cbc/internal/domain/service"
	infra "github.com/turtacn/cbc/internal/infrastructure/ratelimit"
)

type ServiceAdapter struct{ RL *infra.RedisRateLimiter }

// Compile-time check:
var _ domain.RateLimitService = (*ServiceAdapter)(nil)

func (a *ServiceAdapter) Allow(
	ctx context.Context,
	dim domain.RateLimitDimension,
	identifier string,
	action string,
) (bool, int, time.Time, error) {
	return a.RL.Allow(ctx, dim, identifier, action)
}

func (a *ServiceAdapter) AllowN(
	ctx context.Context,
	dimension domain.RateLimitDimension,
	identifier string,
	action string,
	n int,
) (allowed bool, remaining int, resetAt time.Time, err error) {
	return a.RL.AllowN(ctx, dimension, identifier, action, n)
}
func (a *ServiceAdapter) ResetLimit(
	ctx context.Context,
	dimension domain.RateLimitDimension,
	identifier string,
	action string,
) error {
	return a.RL.ResetLimit(ctx, dimension, identifier, action)
}
func (a *ServiceAdapter) GetCurrentUsage(
	ctx context.Context,
	dimension domain.RateLimitDimension,
	identifier string,
	action string,
) (usage int, limit int, resetAt time.Time, err error) {
	// choose sensible defaults; you can make these configurable later
	const defaultLimit int64 = 60
	res, err := a.RL.GetCurrentUsage(ctx, dimension, identifier, defaultLimit)
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	return int(res.Used), int(res.Limit), res.ResetAt, nil
}

func (a *ServiceAdapter) SetCustomLimit(
	ctx context.Context,
	dimension domain.RateLimitDimension,
	identifier string,
	action string,
	limit int,
	window int64,
	ttl int64,
) error {
	return nil
}

func (a *ServiceAdapter) GetLimitConfig(
	ctx context.Context,
	dimension domain.RateLimitDimension,
	action string,
) (*domain.RateLimitConfig, error) {
	return nil, nil
}
func (a *ServiceAdapter) IncrementCounter(
	ctx context.Context,
	dimension domain.RateLimitDimension,
	identifier string,
	action string,
	increment int,
) (int, error) {
	return 0, nil
}
func (a *ServiceAdapter) DecayCounter(
	ctx context.Context,
	dimension domain.RateLimitDimension,
	identifier string,
	action string,
) error {
	return nil
}
