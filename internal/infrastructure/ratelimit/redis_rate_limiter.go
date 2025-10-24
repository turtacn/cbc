package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

type redisRateLimiter struct {
	redisClient *redis.RedisConnection
	log         logger.Logger
}

// NewRedisRateLimiter creates a new Redis-based rate limiter.
func NewRedisRateLimiter(redisClient *redis.RedisConnection, log logger.Logger) service.RateLimitService {
	return &redisRateLimiter{
		redisClient: redisClient,
		log:         log,
	}
}

var allowScript = redis.NewScript(`
	local key = KEYS[1]
	local capacity = tonumber(ARGV[1])
	local rate = tonumber(ARGV[2])
	local requested_tokens = tonumber(ARGV[3])

	local bucket_info = redis.call("HMGET", key, "tokens", "last_update")
	local tokens = tonumber(bucket_info[1])
	local last_update = tonumber(bucket_info[2])

	if tokens == nil then
		tokens = capacity
		last_update = 0
	end

	local now = redis.call("TIME")
	local current_time = tonumber(now[1]) + tonumber(now[2]) / 1000000

	if last_update == 0 then
		last_update = current_time
	end

	local elapsed = current_time - last_update
	local new_tokens = elapsed * rate
	tokens = math.min(capacity, tokens + new_tokens)

	if tokens >= requested_tokens then
		tokens = tokens - requested_tokens
		redis.call("HMSET", key, "tokens", tokens, "last_update", current_time)
		redis.call("EXPIRE", key, math.ceil(capacity / rate * 2)) -- Expire key to prevent memory leaks
		return 1
	else
		return 0
	end
`)

func (r *redisRateLimiter) Allow(ctx context.Context, scope constants.RateLimitScope, identifier string) (bool, *errors.AppError) {
	// A real implementation would fetch capacity and rate from tenant config
	capacity, rate := 100.0, 10.0

	key := fmt.Sprintf("ratelimit:%s:%s", scope, identifier)

	result, err := allowScript.Run(ctx, r.redisClient.Client, []string{key}, capacity, rate, 1).Result()
	if err != nil {
		r.log.Error(ctx, "Redis rate limiter script failed", err)
		return false, errors.ErrCache.WithError(err)
	}

	return result.(int64) == 1, nil
}

func (r *redisRateLimiter) ResetLimit(ctx context.Context, scope constants.RateLimitScope, identifier string) *errors.AppError {
	key := fmt.Sprintf("ratelimit:%s:%s", scope, identifier)
	if err := r.redisClient.Client.Del(ctx, key).Err(); err != nil {
		return errors.ErrCache.WithError(err)
	}
	return nil
}

func (r *redisRateLimiter) GetCurrentUsage(ctx context.Context, scope constants.RateLimitScope, identifier string) (int, *errors.AppError) {
	// This is a simplified version; a real implementation would be more complex.
	return 0, nil
}
//Personal.AI order the ending