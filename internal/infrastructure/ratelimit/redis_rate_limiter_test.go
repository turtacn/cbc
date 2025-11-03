// internal/infrastructure/ratelimit/redis_rate_limiter_test.go
package ratelimit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// setup starts a miniredis server and returns a Redis client
func setup(t *testing.T) *redis.Client {
	s, err := miniredis.Run()
	require.NoError(t, err)

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	t.Cleanup(func() {
		s.Close()
		client.Close()
	})

	return client
}

// TestRedisRateLimiter_Allow verifies basic rate limiting
func TestRedisRateLimiter_Allow(t *testing.T) {
	client := setup(t)
	log := logger.NewDefaultLogger()
	config := DefaultRateLimiterConfig()
	config.DefaultLimit = 3
	config.DefaultWindow = time.Second * 2
	limiter, err := NewRedisRateLimiter(client, config, log)
	require.NoError(t, err)

	ctx := context.Background()
	key := "test_allow"

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		allowed, remaining, _, err := limiter.Allow(ctx, service.RateLimitDimensionUser, key, "default")
		require.NoError(t, err)
		assert.True(t, allowed)
		assert.Equal(t, 3-i-1, remaining)
	}

	// 4th request should be denied
	allowed, _, resetAt, err := limiter.Allow(ctx, service.RateLimitDimensionUser, key, "default")
	require.NoError(t, err)
	assert.False(t, allowed)
	assert.WithinDuration(t, time.Now().Add(config.DefaultWindow), resetAt, time.Second)
}

// TestRedisRateLimiter_AllowN verifies allowing multiple requests at once
func TestRedisRateLimiter_AllowN(t *testing.T) {
	client := setup(t)
	log := logger.NewDefaultLogger()
	config := DefaultRateLimiterConfig()
	config.DefaultLimit = 5
	limiter, err := NewRedisRateLimiter(client, config, log)
	require.NoError(t, err)

	ctx := context.Background()
	key := "test_allow_n"

	// Allow 2 requests, should succeed
	allowed, remaining, _, err := limiter.AllowN(ctx, service.RateLimitDimensionUser, key, "default", 2)
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, 3, remaining)

	// Allow 4 requests, should fail
	allowed, _, _, err = limiter.AllowN(ctx, service.RateLimitDimensionUser, key, "default", 4)
	require.NoError(t, err)
	assert.False(t, allowed)
}

// TestRedisRateLimiter_AllowWithExpiration verifies that the rate limit resets after the window
func TestRedisRateLimiter_AllowWithExpiration(t *testing.T) {
	client := setup(t)
	log := logger.NewDefaultLogger()
	config := DefaultRateLimiterConfig()
	config.DefaultLimit = 2
	config.DefaultWindow = 200 * time.Millisecond
	limiter, err := NewRedisRateLimiter(client, config, log)
	require.NoError(t, err)

	ctx := context.Background()
	key := fmt.Sprintf("test:%d", time.Now().UnixNano())

	// Exhaust the limit
	_, _, _, err = limiter.Allow(ctx, service.RateLimitDimensionUser, key, "default")
	require.NoError(t, err)
	allowed, remaining, _, err := limiter.Allow(ctx, service.RateLimitDimensionUser, key, "default")
	require.NoError(t, err)
	require.True(t, allowed)
	require.Equal(t, 0, remaining)

	// Wait for the window to expire
	time.Sleep(220 * time.Millisecond)

	// Next request should be allowed
	allowed, remaining, _, err = limiter.Allow(ctx, service.RateLimitDimensionUser, key, "default")
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, 1, remaining)
}

// TestRedisRateLimiter_ResetLimit verifies resetting the rate limit
func TestRedisRateLimiter_ResetLimit(t *testing.T) {
	client := setup(t)
	log := logger.NewNoopLogger()
	config := DefaultRateLimiterConfig()
	config.DefaultLimit = 1
	limiter, err := NewRedisRateLimiter(client, config, log)
	require.NoError(t, err)

	ctx := context.Background()
	key := "test_reset"

	// Exhaust the limit
	allowed, _, _, err := limiter.Allow(ctx, service.RateLimitDimensionUser, key, "default")
	require.NoError(t, err)
	assert.True(t, allowed, "first request should be allowed")

	// 2nd request should be denied
	allowed, _, _, err = limiter.Allow(ctx, service.RateLimitDimensionUser, key, "default")
	require.NoError(t, err)
	assert.False(t, allowed, "second request should be denied")

	// Reset the limit
	err = limiter.ResetLimit(ctx, service.RateLimitDimensionUser, key, "default")
	require.NoError(t, err)

	// Verify key is deleted
	redisKey := fmt.Sprintf("ratelimit:%s:%s:%s", service.RateLimitDimensionUser, key, "default")
	exists, err := client.Exists(ctx, redisKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "redis key should be deleted after reset")

	// Next request should be allowed
	allowed, _, _, err = limiter.Allow(ctx, service.RateLimitDimensionUser, key, "default")
	require.NoError(t, err)
	assert.True(t, allowed, "request after reset should be allowed")
}
