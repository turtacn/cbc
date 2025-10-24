// Package ratelimit provides distributed rate limiting using Redis.
package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// RateLimitDimension represents different dimensions for rate limiting.
type RateLimitDimension string

const (
	// DimensionTenant applies rate limit per tenant
	DimensionTenant RateLimitDimension = "tenant"
	// DimensionDevice applies rate limit per device
	DimensionDevice RateLimitDimension = "device"
	// DimensionIP applies rate limit per IP address
	DimensionIP RateLimitDimension = "ip"
	// DimensionUser applies rate limit per user
	DimensionUser RateLimitDimension = "user"
)

// RedisRateLimiter implements distributed rate limiting using Redis.
type RedisRateLimiter struct {
	client       redis.UniversalClient
	logger       logger.Logger
	config       *RateLimiterConfig
	localBuckets *TokenBucketPool // Fallback for Redis failures
}

// RateLimiterConfig holds rate limiter configuration.
type RateLimiterConfig struct {
	// DefaultLimit is the default request limit
	DefaultLimit int64
	// DefaultWindow is the time window for rate limiting
	DefaultWindow time.Duration
	// EnableLocalFallback enables local token bucket fallback
	EnableLocalFallback bool
	// KeyPrefix is the Redis key prefix
	KeyPrefix string
}

// RateLimitResult represents the result of a rate limit check.
type RateLimitResult struct {
	// Allowed indicates if the request is allowed
	Allowed bool
	// Limit is the maximum number of requests allowed
	Limit int64
	// Remaining is the number of requests remaining
	Remaining int64
	// ResetAt is the time when the limit resets
	ResetAt time.Time
	// RetryAfter is the duration to wait before retrying
	RetryAfter time.Duration
}

// RateLimitUsage represents current usage statistics.
type RateLimitUsage struct {
	// Key is the rate limit key
	Key string
	// Used is the number of requests used
	Used int64
	// Limit is the maximum allowed
	Limit int64
	// Remaining is the number remaining
	Remaining int64
	// ResetAt is when the counter resets
	ResetAt time.Time
	// Percentage is the usage percentage
	Percentage float64
}

// Lua script for atomic token bucket operations
const tokenBucketLuaScript = `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local requested = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

-- Get current state
local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1]) or capacity
local last_refill = tonumber(bucket[2]) or now

-- Calculate tokens to add based on elapsed time
local elapsed = now - last_refill
local tokens_to_add = elapsed * rate / 1000  -- rate is per second, elapsed in ms

-- Refill tokens
tokens = math.min(tokens + tokens_to_add, capacity)

-- Check if we have enough tokens
local allowed = 0
local remaining = tokens
if tokens >= requested then
    tokens = tokens - requested
    remaining = tokens
    allowed = 1
end

-- Calculate reset time (time until bucket is full)
local reset_ms = 0
if tokens < capacity then
    reset_ms = math.ceil((capacity - tokens) / rate * 1000)
end

-- Update state
redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
redis.call('PEXPIRE', key, reset_ms + 60000)  -- Expire 1 minute after full

return {allowed, math.floor(remaining), math.floor(capacity), reset_ms}
`

// NewRedisRateLimiter creates a new Redis-based rate limiter.
//
// Parameters:
//   - client: Redis client
//   - config: Rate limiter configuration
//   - log: Logger instance
//
// Returns:
//   - *RedisRateLimiter: Initialized rate limiter
//   - error: Initialization error if any
func NewRedisRateLimiter(
	client redis.UniversalClient,
	config *RateLimiterConfig,
	log logger.Logger,
) (*RedisRateLimiter, error) {
	if client == nil {
		return nil, errors.New(errors.CodeInvalidArgument, "redis client is required")
	}

	if config == nil {
		config = DefaultRateLimiterConfig()
	}

	rl := &RedisRateLimiter{
		client: client,
		logger: log,
		config: config,
	}

	// Initialize local fallback if enabled
	if config.EnableLocalFallback {
		rl.localBuckets = NewTokenBucketPool(TokenBucketConfig{
			Capacity: float64(config.DefaultLimit),
			Rate:     float64(config.DefaultLimit) / config.DefaultWindow.Seconds(),
		})
	}

	log.Info("Redis rate limiter initialized",
		"default_limit", config.DefaultLimit,
		"default_window", config.DefaultWindow,
		"local_fallback", config.EnableLocalFallback,
	)

	return rl, nil
}

// DefaultRateLimiterConfig returns default rate limiter configuration.
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		DefaultLimit:        int64(constants.DefaultRateLimitPerMinute),
		DefaultWindow:       time.Minute,
		EnableLocalFallback: true,
		KeyPrefix:           "ratelimit",
	}
}

// Allow checks if a request is allowed under the rate limit.
//
// Parameters:
//   - ctx: Context for timeout control
//   - dimension: Rate limit dimension (tenant, device, IP, user)
//   - identifier: Identifier for the dimension
//   - limit: Maximum requests allowed (0 uses default)
//   - window: Time window for rate limiting (0 uses default)
//
// Returns:
//   - *RateLimitResult: Rate limit check result
//   - error: Check error if any
func (rl *RedisRateLimiter) Allow(
	ctx context.Context,
	dimension RateLimitDimension,
	identifier string,
	limit int64,
	window time.Duration,
) (*RateLimitResult, error) {
	// Use defaults if not specified
	if limit <= 0 {
		limit = rl.config.DefaultLimit
	}
	if window <= 0 {
		window = rl.config.DefaultWindow
	}

	// Build rate limit key
	key := rl.buildKey(dimension, identifier)

	// Calculate rate in tokens per second
	rate := float64(limit) / window.Seconds()

	// Execute Lua script for atomic operation
	now := time.Now()
	result, err := rl.executeLuaScript(ctx, key, limit, rate, 1, now)
	if err != nil {
		// Fallback to local bucket if Redis fails
		if rl.config.EnableLocalFallback {
			return rl.allowLocal(key, limit, rate)
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "rate limit check failed")
	}

	return result, nil
}

// AllowN checks if N requests are allowed under the rate limit.
//
// Parameters:
//   - ctx: Context for timeout control
//   - dimension: Rate limit dimension
//   - identifier: Identifier for the dimension
//   - n: Number of requests to check
//   - limit: Maximum requests allowed
//   - window: Time window for rate limiting
//
// Returns:
//   - *RateLimitResult: Rate limit check result
//   - error: Check error if any
func (rl *RedisRateLimiter) AllowN(
	ctx context.Context,
	dimension RateLimitDimension,
	identifier string,
	n int64,
	limit int64,
	window time.Duration,
) (*RateLimitResult, error) {
	if limit <= 0 {
		limit = rl.config.DefaultLimit
	}
	if window <= 0 {
		window = rl.config.DefaultWindow
	}

	key := rl.buildKey(dimension, identifier)
	rate := float64(limit) / window.Seconds()

	now := time.Now()
	result, err := rl.executeLuaScript(ctx, key, limit, rate, n, now)
	if err != nil {
		if rl.config.EnableLocalFallback {
			return rl.allowLocalN(key, limit, rate, n)
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "rate limit check failed")
	}

	return result, nil
}

// ResetLimit resets the rate limit for a specific key.
//
// Parameters:
//   - ctx: Context for timeout control
//   - dimension: Rate limit dimension
//   - identifier: Identifier for the dimension
//
// Returns:
//   - error: Reset error if any
func (rl *RedisRateLimiter) ResetLimit(
	ctx context.Context,
	dimension RateLimitDimension,
	identifier string,
) error {
	key := rl.buildKey(dimension, identifier)

	err := rl.client.Del(ctx, key).Err()
	if err != nil && err != redis.Nil {
		return errors.Wrap(err, errors.CodeInternal, "failed to reset rate limit")
	}

	// Also reset local bucket if exists
	if rl.localBuckets != nil {
		rl.localBuckets.Remove(key)
	}

	rl.logger.Debug("Rate limit reset",
		"dimension", dimension,
		"identifier", identifier,
		"key", key,
	)

	return nil
}

// GetCurrentUsage retrieves current usage statistics.
//
// Parameters:
//   - ctx: Context for timeout control
//   - dimension: Rate limit dimension
//   - identifier: Identifier for the dimension
//   - limit: Maximum requests allowed
//
// Returns:
//   - *RateLimitUsage: Current usage statistics
//   - error: Retrieval error if any
func (rl *RedisRateLimiter) GetCurrentUsage(
	ctx context.Context,
	dimension RateLimitDimension,
	identifier string,
	limit int64,
) (*RateLimitUsage, error) {
	if limit <= 0 {
		limit = rl.config.DefaultLimit
	}

	key := rl.buildKey(dimension, identifier)

	// Get current state from Redis
	values, err := rl.client.HMGet(ctx, key, "tokens", "last_refill").Result()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get usage")
	}

	// Parse values
	var tokens float64 = float64(limit) // Default to full
	var lastRefill int64 = time.Now().UnixMilli()

	if len(values) >= 2 {
		if tokensStr, ok := values[0].(string); ok {
			if t, err := strconv.ParseFloat(tokensStr, 64); err == nil {
				tokens = t
			}
		}
		if refillStr, ok := values[1].(string); ok {
			if r, err := strconv.ParseInt(refillStr, 10, 64); err == nil {
				lastRefill = r
			}
		}
	}

	// Calculate usage
	used := int64(float64(limit) - tokens)
	remaining := int64(tokens)
	if remaining < 0 {
		remaining = 0
	}

	percentage := float64(used) / float64(limit) * 100.0
	if percentage > 100.0 {
		percentage = 100.0
	}

	// Calculate reset time
	resetAt := time.Unix(0, lastRefill*int64(time.Millisecond))
	if tokens < float64(limit) {
		rate := float64(limit) / rl.config.DefaultWindow.Seconds()
		tokensNeeded := float64(limit) - tokens
		resetDuration := time.Duration(tokensNeeded / rate * float64(time.Second))
		resetAt = time.Now().Add(resetDuration)
	}

	usage := &RateLimitUsage{
		Key:        key,
		Used:       used,
		Limit:      limit,
		Remaining:  remaining,
		ResetAt:    resetAt,
		Percentage: percentage,
	}

	return usage, nil
}

// CheckTenantLimit checks rate limit for a tenant.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//   - config: Tenant rate limit configuration
//
// Returns:
//   - *RateLimitResult: Rate limit result
//   - error: Check error if any
func (rl *RedisRateLimiter) CheckTenantLimit(
	ctx context.Context,
	tenantID string,
	config *models.RateLimitConfig,
) (*RateLimitResult, error) {
	limit := int64(constants.DefaultRateLimitPerMinute)
	window := time.Minute

	if config != nil && config.RequestsPerMinute > 0 {
		limit = int64(config.RequestsPerMinute)
	}

	return rl.Allow(ctx, DimensionTenant, tenantID, limit, window)
}

// CheckDeviceLimit checks rate limit for a device.
//
// Parameters:
//   - ctx: Context for timeout control
//   - deviceID: Device identifier
//   - limit: Maximum requests allowed
//
// Returns:
//   - *RateLimitResult: Rate limit result
//   - error: Check error if any
func (rl *RedisRateLimiter) CheckDeviceLimit(
	ctx context.Context,
	deviceID string,
	limit int64,
) (*RateLimitResult, error) {
	return rl.Allow(ctx, DimensionDevice, deviceID, limit, time.Minute)
}

// CheckIPLimit checks rate limit for an IP address.
//
// Parameters:
//   - ctx: Context for timeout control
//   - ip: IP address
//   - limit: Maximum requests allowed
//
// Returns:
//   - *RateLimitResult: Rate limit result
//   - error: Check error if any
func (rl *RedisRateLimiter) CheckIPLimit(
	ctx context.Context,
	ip string,
	limit int64,
) (*RateLimitResult, error) {
	return rl.Allow(ctx, DimensionIP, ip, limit, time.Minute)
}

// executeLuaScript executes the token bucket Lua script.
func (rl *RedisRateLimiter) executeLuaScript(
	ctx context.Context,
	key string,
	capacity int64,
	rate float64,
	requested int64,
	now time.Time,
) (*RateLimitResult, error) {
	nowMs := now.UnixMilli()

	// Execute Lua script
	result, err := rl.client.Eval(ctx, tokenBucketLuaScript, []string{key},
		capacity, rate, requested, nowMs).Result()
	if err != nil {
		return nil, err
	}

	// Parse result
	resultSlice, ok := result.([]interface{})
	if !ok || len(resultSlice) < 4 {
		return nil, fmt.Errorf("invalid Lua script result")
	}

	allowed := resultSlice[0].(int64) == 1
	remaining := resultSlice[1].(int64)
	limit := resultSlice[2].(int64)
	resetMs := resultSlice[3].(int64)

	resetAt := now.Add(time.Duration(resetMs) * time.Millisecond)
	retryAfter := time.Duration(0)
	if !allowed && resetMs > 0 {
		retryAfter = time.Duration(resetMs) * time.Millisecond
	}

	return &RateLimitResult{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		ResetAt:    resetAt,
		RetryAfter: retryAfter,
	}, nil
}

// allowLocal uses local token bucket as fallback.
func (rl *RedisRateLimiter) allowLocal(key string, limit int64, rate float64) (*RateLimitResult, error) {
	bucket := rl.localBuckets.GetOrCreate(key)

	// Update bucket configuration if needed
	if bucket.Capacity() != float64(limit) || bucket.Rate() != rate {
		bucket.SetCapacity(float64(limit))
		bucket.SetRate(rate)
	}

	allowed := bucket.Allow()
	remaining := int64(bucket.Available())
	resetDuration := bucket.TimeUntilAvailable(float64(limit))

	return &RateLimitResult{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		ResetAt:    time.Now().Add(resetDuration),
		RetryAfter: resetDuration,
	}, nil
}

// allowLocalN uses local token bucket for N requests.
func (rl *RedisRateLimiter) allowLocalN(key string, limit int64, rate float64, n int64) (*RateLimitResult, error) {
	bucket := rl.localBuckets.GetOrCreate(key)

	if bucket.Capacity() != float64(limit) || bucket.Rate() != rate {
		bucket.SetCapacity(float64(limit))
		bucket.SetRate(rate)
	}

	allowed := bucket.AllowN(float64(n))
	remaining := int64(bucket.Available())
	resetDuration := bucket.TimeUntilAvailable(float64(limit))

	return &RateLimitResult{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		ResetAt:    time.Now().Add(resetDuration),
		RetryAfter: resetDuration,
	}, nil
}

// buildKey builds a Redis key for rate limiting.
func (rl *RedisRateLimiter) buildKey(dimension RateLimitDimension, identifier string) string {
	return fmt.Sprintf("%s:%s:%s", rl.config.KeyPrefix, dimension, identifier)
}

// CleanupLocalBuckets performs cleanup of idle local buckets.
//
// Parameters:
//   - maxIdle: Maximum idle duration
//
// Returns:
//   - int: Number of buckets cleaned up
func (rl *RedisRateLimiter) CleanupLocalBuckets(maxIdle time.Duration) int {
	if rl.localBuckets == nil {
		return 0
	}

	removed := rl.localBuckets.Cleanup(maxIdle)
	if removed > 0 {
		rl.logger.Debug("Cleaned up idle buckets", "count", removed)
	}

	return removed
}

// Close closes the rate limiter and releases resources.
func (rl *RedisRateLimiter) Close() error {
	if rl.localBuckets != nil {
		rl.localBuckets.Clear()
	}

	rl.logger.Info("Redis rate limiter closed")
	return nil
}

//Personal.AI order the ending
