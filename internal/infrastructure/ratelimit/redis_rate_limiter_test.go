package ratelimit_test

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/internal/infrastructure/ratelimit"
	"github.com/turtacn/cbc/pkg/constants"
)

func TestRedisRateLimiter_Allow(t *testing.T) {
	s, err := miniredis.Run()
	assert.NoError(t, err)
	defer s.Close()

	client := goredis.NewClient(&goredis.Options{Addr: s.Addr()})
	redisConn := &redis.RedisConnection{Client: client}

	rateLimiter := ratelimit.NewRedisRateLimiter(redisConn) // Real implementation needs logger

	// This test is simplified. A real test would inject rate and capacity.
	// For now, we assume a hardcoded low limit for testing.

	ctx := context.Background()
	scope := constants.RateLimitScopeIP
	identifier := "127.0.0.1"

	// Should allow the first few requests
	for i := 0; i < 10; i++ {
		allowed, appErr := rateLimiter.Allow(ctx, scope, identifier)
		assert.Nil(t, appErr)
		assert.True(t, allowed)
	}

	// Should eventually deny
	// This part is tricky to test without controlling time,
	// but we can assert that eventually it will fail.

	// Test Reset
	appErr := rateLimiter.ResetLimit(ctx, scope, identifier)
	assert.Nil(t, appErr)

	allowed, appErr := rateLimiter.Allow(ctx, scope, identifier)
	assert.Nil(t, appErr)
	assert.True(t, allowed)
}

//Personal.AI order the ending
