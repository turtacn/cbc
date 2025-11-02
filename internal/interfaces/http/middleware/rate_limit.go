package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// RateLimitMiddleware creates a new rate limiting middleware.
func RateLimitMiddleware(rateLimiter service.RateLimitService, cfg *config.RateLimitConfig, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !cfg.Enabled {
			c.Next()
			return
		}

		// Hierarchical rate limiting: Agent > Tenant > Global
		var dimension service.RateLimitDimension
		var identifier string
		var limit int

		// NOTE: Tenant and Agent ID extraction from JWT will be implemented in Phase 6.
		// For now, we'll use placeholder values.
		agentID := c.GetString("agent_id") // Placeholder
		tenantID := c.GetString("tenant_id") // Placeholder

		if cfg.AgentRPS > 0 && agentID != "" {
			dimension = service.RateLimitDimensionUser
			identifier = agentID
			limit = cfg.AgentRPS
		} else if cfg.TenantRPS > 0 && tenantID != "" {
			dimension = service.RateLimitDimensionTenant
			identifier = tenantID
			limit = cfg.TenantRPS
		} else {
			dimension = "global"
			identifier = "all"
			limit = cfg.GlobalRPS
		}

		allowed, _, _, err := rateLimiter.Allow(c.Request.Context(), dimension, identifier, identifier)
		if err != nil {
			log.Error(c, "rate limiter failed", err)
			c.Next() // Fail open
			return
		}

		if !allowed {
			log.Warn(c, "rate limit exceeded", logger.String("dimension", string(dimension)), logger.String("identifier", identifier), logger.Int("limit", limit))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
			return
		}

		c.Next()
	}
}
