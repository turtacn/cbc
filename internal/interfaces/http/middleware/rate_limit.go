package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// RateLimitMiddleware returns a Gin middleware that provides hierarchical rate limiting.
// It prioritizes limits in the following order: by Agent ID, then by Tenant ID, and finally a global limit.
// The identifiers (agentID, tenantID) are expected to be injected into the context by a preceding authentication middleware.
// If the rate limiting service fails, the middleware will "fail open" (allow the request) to maintain availability.
// RateLimitMiddleware 返回一个提供分层速率限制的 Gin 中-ian-ware。
// 它按以下顺序优先处理限制：按代理 ID，然后按租户 ID，最后是全局限制。
// 标识符（agentID、tenantID）应由前面的身份验证中间件注入到上下文中。
// 如果速率限制服务失败，中间件将“失败打开”（允许请求）以保持可用性。
func RateLimitMiddleware(rateLimiter service.RateLimitService, cfg *config.RateLimitConfig, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !cfg.Enabled {
			c.Next()
			return
		}

		// Apply hierarchical rate limiting: Agent > Tenant > Global.
		var dimension service.RateLimitDimension
		var identifier string
		var limit int

		// Attempt to get agent and tenant IDs from the context, set by the JWT auth middleware.
		agentID := c.GetString("agent_id")
		tenantID := c.GetString("tenant_id")

		if cfg.AgentRPS > 0 && agentID != "" {
			dimension = service.RateLimitDimensionUser
			identifier = agentID
			limit = cfg.AgentRPS
		} else if cfg.TenantRPS > 0 && tenantID != "" {
			dimension = service.RateLimitDimensionTenant
			identifier = tenantID
			limit = cfg.TenantRPS
		} else {
			// Fallback to a global limit if no specific identifiers are found.
			dimension = "global"
			identifier = "all"
			limit = cfg.GlobalRPS
		}

		// Check with the rate limiting service if the request is allowed.
		allowed, _, _, err := rateLimiter.Allow(c.Request.Context(), dimension, identifier, identifier)
		if err != nil {
			log.Error(c, "Rate limiter service failed, failing open", err, logger.String("dimension", string(dimension)), logger.String("identifier", identifier))
			c.Next() // Fail open to prioritize availability.
			return
		}

		if !allowed {
			log.Warn(c, "Rate limit exceeded", logger.String("dimension", string(dimension)), logger.String("identifier", identifier), logger.Int("limit", limit))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too_many_requests", "description": "Rate limit exceeded."})
			return
		}

		c.Next()
	}
}
