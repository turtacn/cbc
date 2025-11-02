package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/pkg/logger"
)

// IdempotencyMiddleware creates a middleware for idempotency checks.
func IdempotencyMiddleware(redisClient redis.UniversalClient, cfg *config.IdempotencyConfig, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !cfg.Enabled {
			c.Next()
			return
		}

		// Extract JTI from the client_assertion
		clientAssertion := c.PostForm("client_assertion")
		if clientAssertion == "" {
			// If no client_assertion is present, this middleware does not apply.
			c.Next()
			return
		}

		// Parse the JWT without verification to get the claims.
		// Verification of the assertion is the responsibility of the application logic.
		token, _, err := new(jwt.Parser).ParseUnverified(clientAssertion, jwt.MapClaims{})
		if err != nil {
			log.Warn(c, "could not parse client_assertion", logger.Error(err))
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_client_assertion"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Warn(c, "could not read claims from client_assertion")
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_client_assertion"})
			return
		}

		jti, ok := claims["jti"].(string)
		if !ok || strings.TrimSpace(jti) == "" {
			log.Warn(c, "jti is missing from client_assertion")
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_client_assertion", "error_description": "jti is missing"})
			return
		}

		// Check if the JTI has been used before
		key := "jti:" + jti
		set, err := redisClient.SetNX(c.Request.Context(), key, true, cfg.RedisCacheTTL).Result()
		if err != nil {
			log.Error(c, "redis check for jti failed", err)
			c.Next() // Fail open
			return
		}

		if !set {
			log.Warn(c, "replay attack detected", logger.String("jti", jti))
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "jti_already_used"})
			return
		}

		c.Next()
	}
}
