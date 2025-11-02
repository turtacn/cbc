//go:build test
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/infrastructure/ratelimit"
	"github.com/turtacn/cbc/pkg/logger"
)

func TestRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.NewNullLogger()

	// Setup miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	rateLimiter, err := ratelimit.NewRedisRateLimiter(redisClient, &ratelimit.RateLimiterConfig{}, log)
	if err != nil {
		t.Fatalf("failed to create rate limiter: %v", err)
	}

	t.Run("should allow request when limit is not exceeded", func(t *testing.T) {
		cfg := &config.RateLimitConfig{
			Enabled:   true,
			GlobalRPS: 10,
		}
		router := gin.New()
		router.Use(RateLimitMiddleware(rateLimiter, cfg, log))
		router.GET("/", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should deny request when limit is exceeded", func(t *testing.T) {
		// Ensure redis is clean for this test
		mr.FlushAll()

		cfg := &config.RateLimitConfig{
			Enabled:   true,
			GlobalRPS: 1, // 1 request per second
		}
		router := gin.New()
		router.Use(RateLimitMiddleware(rateLimiter, cfg, log))
		router.GET("/", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		// First request should be allowed
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodGet, "/", nil)
		router.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Second request within the same window should be denied
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodGet, "/", nil)
		router.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusTooManyRequests, w2.Code)

		// Wait for the window to reset
		mr.FastForward(1 * time.Second)

		// Third request should be allowed again
		w3 := httptest.NewRecorder()
		req3, _ := http.NewRequest(http.MethodGet, "/", nil)
		router.ServeHTTP(w3, req3)
		assert.Equal(t, http.StatusOK, w3.Code)
	})

	t.Run("should not rate limit when disabled", func(t *testing.T) {
		cfg := &config.RateLimitConfig{
			Enabled: false,
		}
		router := gin.New()
		router.Use(RateLimitMiddleware(rateLimiter, cfg, log))
		router.GET("/", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
