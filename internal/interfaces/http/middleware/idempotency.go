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

// IdempotencyMiddleware returns a Gin middleware to prevent duplicate requests (replay attacks).
// It works by extracting the JWT ID (JTI) from the `client_assertion` form parameter, which is expected to be a JWT.
// It then uses Redis to check if this JTI has been seen before. If so, it rejects the request with a 409 Conflict status.
// This ensures that a single client assertion cannot be used to make multiple identical requests.
// IdempotencyMiddleware 返回一个 Gin 中间件以防止重复请求（重放攻击）。
// 它的工作原理是从 `client_assertion` 表单参数中提取 JWT ID (JTI)，该参数应为一个 JWT。
// 然后，它使用 Redis 检查此 JTI 是否先前已被使用过。如果是，它将以 409 Conflict 状态拒绝该请求。
// 这确保了单个客户端断言不能用于发出多个相同的请求。
func IdempotencyMiddleware(redisClient redis.UniversalClient, cfg *config.IdempotencyConfig, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !cfg.Enabled {
			c.Next()
			return
		}

		// Extract the client assertion JWT from the form body.
		clientAssertion := c.PostForm("client_assertion")
		if clientAssertion == "" {
			// If no client assertion is present, this middleware does not apply.
			c.Next()
			return
		}

		// Parse the JWT without cryptographic verification to access its claims.
		// The actual signature verification is the responsibility of the application logic later on.
		// This middleware is only concerned with the JTI for replay protection.
		token, _, err := new(jwt.Parser).ParseUnverified(clientAssertion, jwt.MapClaims{})
		if err != nil {
			log.Warn(c, "Could not parse client_assertion JWT for idempotency check", logger.Error(err))
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "malformed client_assertion"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Warn(c, "Could not read claims from client_assertion for idempotency check")
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "invalid claims in client_assertion"})
			return
		}

		jti, ok := claims["jti"].(string)
		if !ok || strings.TrimSpace(jti) == "" {
			log.Warn(c, "JTI claim is missing or empty in client_assertion for idempotency check")
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "jti claim is required in client_assertion"})
			return
		}

		// Use Redis SETNX to atomically check and set the JTI.
		// This prevents race conditions where two identical requests are processed simultaneously.
		key := "jti:" + jti
		isNew, err := redisClient.SetNX(c.Request.Context(), key, true, cfg.RedisCacheTTL).Result()
		if err != nil {
			log.Error(c, "Redis check for JTI idempotency failed", err, logger.String("jti", jti))
			c.Next() // Fail open: If Redis is down, we allow the request to proceed.
			return
		}

		if !isNew {
			// If the key already existed, this is a replay.
			log.Warn(c, "Replay attack detected: JTI has already been used", logger.String("jti", jti))
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "jti_already_used", "error_description": "This request has already been processed."})
			return
		}

		c.Next()
	}
}
