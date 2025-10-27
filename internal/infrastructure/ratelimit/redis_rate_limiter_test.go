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
	limiter, err := NewRedisRateLimiter(client, config, log)
	require.NoError(t, err)

	ctx := context.Background()
	key := "test_allow"
	limit := int64(3)
	window := time.Second * 2

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		res, err := limiter.Allow(ctx, DimensionDevice, key, limit, window)
		require.NoError(t, err)
		assert.True(t, res.Allowed)
		assert.Equal(t, limit, res.Limit)
		assert.Equal(t, limit-int64(i)-1, res.Remaining)
	}

	// 4th request should be denied
	res, err := limiter.Allow(ctx, DimensionDevice, key, limit, window)
	require.NoError(t, err)
	assert.False(t, res.Allowed)
	assert.Equal(t, limit, res.Limit)
	assert.Equal(t, int64(0), res.Remaining)
	assert.WithinDuration(t, time.Now().Add(window), res.ResetAt, time.Second)
}

// TestRedisRateLimiter_AllowN verifies allowing multiple requests at once
func TestRedisRateLimiter_AllowN(t *testing.T) {
	client := setup(t)
	log := logger.NewDefaultLogger()
	limiter, err := NewRedisRateLimiter(client, DefaultRateLimiterConfig(), log)
	require.NoError(t, err)

	ctx := context.Background()
	key := "test_allow_n"

	// Allow 2 requests, should succeed
	res, err := limiter.AllowN(ctx, DimensionDevice, key, 2, 5, time.Minute)
	require.NoError(t, err)
	assert.True(t, res.Allowed)
	assert.Equal(t, int64(3), res.Remaining)

	// Allow 4 requests, should fail
	res, err = limiter.AllowN(ctx, DimensionDevice, key, 4, 5, time.Minute)
	require.NoError(t, err)
	assert.False(t, res.Allowed)
}

// TestRedisRateLimiter_AllowWithExpiration verifies that the rate limit resets after the window
func TestRedisRateLimiter_AllowWithExpiration(t *testing.T) {
	client := setup(t)
	log := logger.NewDefaultLogger()
	limiter, err := NewRedisRateLimiter(client, DefaultRateLimiterConfig(), log)
	require.NoError(t, err)

	ctx := context.Background()
	key := fmt.Sprintf("test:%d", time.Now().UnixNano())
	limit := int64(2)
	window := 200 * time.Millisecond

	// Exhaust the limit
	_, err = limiter.Allow(ctx, DimensionDevice, key, limit, window)
	require.NoError(t, err)
	res, err := limiter.Allow(ctx, DimensionDevice, key, limit, window)
	require.NoError(t, err)
	require.True(t, res.Allowed)
	require.Equal(t, int64(0), res.Remaining)

	// Wait for the window to expire
	time.Sleep(220 * time.Millisecond)

	// Next request should be allowed
	res2, err := limiter.Allow(ctx, DimensionDevice, key, limit, window)
	require.NoError(t, err)
	assert.True(t, res2.Allowed)
	assert.Equal(t, limit-1, res2.Remaining)
}

// TestRedisRateLimiter_ResetLimit verifies resetting the rate limit
func TestRedisRateLimiter_ResetLimit(t *testing.T) {
	client := setup(t)
	log := logger.NewDefaultLogger()
	limiter, err := NewRedisRateLimiter(client, DefaultRateLimiterConfig(), log)
	require.NoError(t, err)

	ctx := context.Background()
	key := "test_reset"
	limit := int64(1)
	window := time.Minute

	// Exhaust the limit
	_, err = limiter.Allow(ctx, DimensionDevice, key, limit, window)
	require.NoError(t, err)
	res, err := limiter.Allow(ctx, DimensionDevice, key, limit, window)
	require.NoError(t, err)
	require.False(t, res.Allowed)

	// Reset the limit
	err = limiter.ResetLimit(ctx, DimensionDevice, key)
	require.NoError(t, err)

	// Next request should be allowed
	res, err = limiter.Allow(ctx, DimensionDevice, key, limit, window)
	require.NoError(t, err)
	assert.True(t, res.Allowed)
}
