// internal/infrastructure/ratelimit/redis_rate_limiter_test.go
package ratelimit

import (
	"context"
	"sangfor.local/hci/hci-common/utils/redis"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	mr, err := miniredis.Run()
	require.NoError(t, err)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	return mr, client
}

func TestRedisRateLimiter_Allow(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()

	tests := []struct {
		name      string
		key       string
		limit     int
		window    int
		requests  int
		wantAllow []bool
	}{
		{
			name:      "Allow requests within limit",
			key:       "test:user:1",
			limit:     5,
			window:    60,
			requests:  3,
			wantAllow: []bool{true, true, true},
		},
		{
			name:      "Block requests exceeding limit",
			key:       "test:user:2",
			limit:     3,
			window:    60,
			requests:  5,
			wantAllow: []bool{true, true, true, false, false},
		},
		{
			name:      "Single request allowed",
			key:       "test:user:3",
			limit:     1,
			window:    60,
			requests:  1,
			wantAllow: []bool{true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < tt.requests; i++ {
				allowed, err := limiter.Allow(ctx, tt.key, tt.limit, tt.window)
				require.NoError(t, err)
				assert.Equal(t, tt.wantAllow[i], allowed, "Request %d", i+1)
			}
		})
	}
}

func TestRedisRateLimiter_AllowWithExpiration(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()

	key := "test:expiration"
	limit := 2
	window := 1 // 1 second

	// 第一次请求应该被允许
	allowed, err := limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed)

	// 第二次请求应该被允许
	allowed, err = limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed)

	// 第三次请求应该被阻止
	allowed, err = limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.False(t, allowed)

	// 快进时间，等待窗口过期
	mr.FastForward(2 * time.Second)

	// 窗口过期后，请求应该再次被允许
	allowed, err = limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestRedisRateLimiter_Reset(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()

	key := "test:reset"
	limit := 2
	window := 60

	// 达到限流
	limiter.Allow(ctx, key, limit, window)
	limiter.Allow(ctx, key, limit, window)

	allowed, err := limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.False(t, allowed)

	// 重置限流
	err = limiter.Reset(ctx, key)
	require.NoError(t, err)

	// 重置后应该可以再次请求
	allowed, err = limiter.Allow(ctx, key, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestRedisRateLimiter_ConcurrentRequests(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()

	key := "test:concurrent"
	limit := 10
	window := 60
	numGoroutines := 20

	allowedCount := 0
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			allowed, err := limiter.Allow(ctx, key, limit, window)
			require.NoError(t, err)
			if allowed {
				allowedCount++
			}
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// 只有 limit 数量的请求应该被允许
	assert.LessOrEqual(t, allowedCount, limit)
}

func TestRedisRateLimiter_MultipleKeys(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()

	limiter := NewRedisRateLimiter(client)
	ctx := context.Background()

	key1 := "test:user:1"
	key2 := "test:user:2"
	limit := 2
	window := 60

	// key1 达到限流
	limiter.Allow(ctx, key1, limit, window)
	limiter.Allow(ctx, key1, limit, window)

	allowed, err := limiter.Allow(ctx, key1, limit, window)
	require.NoError(t, err)
	assert.False(t, allowed)

	// key2 应该不受影响
	allowed, err = limiter.Allow(ctx, key2, limit, window)
	require.NoError(t, err)
	assert.True(t, allowed)
}
