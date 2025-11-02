//go:build integration
package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/internal/infrastructure/ratelimit"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/internal/interfaces/http/middleware"
	httpRouter "github.com/turtacn/cbc/internal/interfaces/http/router"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/tests/mocks"
	"go.opentelemetry.io/otel"
)

func TestMiddlewareChainE2E(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.NewNoopLogger()
	tracer := otel.Tracer("test-tracer")

	// Setup miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	// Rate limiter
	rateLimiter, err := ratelimit.NewRedisRateLimiter(redisClient, &ratelimit.RateLimiterConfig{}, log)
	if err != nil {
		t.Fatalf("failed to create rate limiter: %v", err)
	}

	// Mocks
	mockAuthApp := new(mocks.MockAuthAppService)

	// Handlers
	authHandler := handlers.NewAuthHandler(mockAuthApp, nil, log)
	deviceHandler := handlers.NewDeviceHandler(nil, nil, log)
	healthHandler := handlers.NewHealthHandler(nil, nil, log)
	jwksHandler := handlers.NewJWKSHandler(nil, log, nil)

	// Middleware
	rateLimitMiddleware := middleware.RateLimitMiddleware(rateLimiter, &config.RateLimitConfig{Enabled: true, GlobalRPS: 5}, log)
	idempotencyMiddleware := middleware.IdempotencyMiddleware(redisClient, &config.IdempotencyConfig{Enabled: true, RedisCacheTTL: 1 * time.Hour}, log)
	observabilityMiddleware := middleware.ObservabilityMiddleware(tracer)

	// Router
	router := httpRouter.NewRouter(&config.Config{}, log, healthHandler, authHandler, deviceHandler, jwksHandler, nil, rateLimitMiddleware, idempotencyMiddleware, observabilityMiddleware)
	router.SetupRoutes()
	engine := router.Engine()

	t.Run("Rate Limiting E2E", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/token", nil)
			engine.ServeHTTP(w, req)
			if w.Code == http.StatusTooManyRequests {
				return
			}
		}
		t.Fatal("expected to be rate limited")
	})

	t.Run("Idempotency E2E", func(t *testing.T) {
		jti := "e2e-jti-1"
		token, _ := createTestJWTWithJti(jti)
		form := url.Values{}
		form.Add("client_assertion", token)

		// First request
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/token", strings.NewReader(form.Encode()))
		req1.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		engine.ServeHTTP(w1, req1)
		assert.NotEqual(t, http.StatusConflict, w1.Code)

		// Second request
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/token", strings.NewReader(form.Encode()))
		req2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		engine.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusConflict, w2.Code)
	})

	t.Run("Observability E2E", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/health/live", nil)
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 1, testutil.CollectAndCount(httpRequestsTotal))
		assert.Equal(t, 1, testutil.CollectAndCount(httpRequestDuration))
	})
}

// createTestJWTWithJti creates a JWT with a specific JTI.
func createTestJWTWithJti(jti string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"jti": jti,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	return token.SignedString([]byte("secret"))
}
