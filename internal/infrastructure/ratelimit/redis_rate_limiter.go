package ratelimit

import (
	"context"
	"sync"

	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
)

type RedisConnection interface{} // stub，只为通过编译

type RedisRateLimiter struct {
	mu sync.Mutex
}

func NewRedisRateLimiter(_ RedisConnection) *RedisRateLimiter {
	return &RedisRateLimiter{}
}

func (r *RedisRateLimiter) Allow(ctx context.Context, scope constants.RateLimitScope, id string) (bool, *errors.AppError) {
	// simple token bucket stub
	r.mu.Lock()
	defer r.mu.Unlock()
	return true, nil
}

func (r *RedisRateLimiter) ResetLimit(ctx context.Context, scope constants.RateLimitScope, identifier string) *errors.AppError {
	return nil
}

func (r *RedisRateLimiter) GetCurrentUsage(ctx context.Context, scope constants.RateLimitScope, identifier string) (int, *errors.AppError) {
	return 0, nil
}
