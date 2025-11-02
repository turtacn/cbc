//go:build test
package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/pkg/logger"
)

// createTestJWTWithJti creates a JWT with a specific JTI.
func createTestJWTWithJti(jti string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"jti": jti,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	return token.SignedString([]byte("secret"))
}

func TestIdempotencyMiddleware(t *testing.T) {
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

	cfg := &config.IdempotencyConfig{
		Enabled:       true,
		RedisCacheTTL: 1 * time.Hour,
	}

	router := gin.New()
	router.Use(IdempotencyMiddleware(redisClient, cfg, log))
	router.POST("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	t.Run("should allow request with new jti", func(t *testing.T) {
		jti := "new-jti"
		token, _ := createTestJWTWithJti(jti)
		form := url.Values{}
		form.Add("client_assertion", token)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should deny request with used jti", func(t *testing.T) {
		jti := "used-jti"
		token, _ := createTestJWTWithJti(jti)
		form := url.Values{}
		form.Add("client_assertion", token)

		// First request
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req1.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		router.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Second request
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		router.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusConflict, w2.Code)
	})

	t.Run("should not check idempotency when disabled", func(t *testing.T) {
		disabledCfg := &config.IdempotencyConfig{Enabled: false}
		disabledRouter := gin.New()
		disabledRouter.Use(IdempotencyMiddleware(redisClient, disabledCfg, log))
		disabledRouter.POST("/", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		jti := "another-jti"
		token, _ := createTestJWTWithJti(jti)
		form := url.Values{}
		form.Add("client_assertion", token)

		// First request
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req1.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		disabledRouter.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Second request
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		disabledRouter.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)
	})
}
