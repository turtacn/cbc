package handlers

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// MiddlewareConfig holds dependencies for middlewares.
type MiddlewareConfig struct {
	RateLimitService service.RateLimitService
	CryptoService    service.CryptoService // Use the domain service interface
	Logger           logger.Logger
	Tracer           trace.Tracer
}

// CORSMiddleware handles cross-origin requests.
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-Trace-ID")
		c.Header("Access-Control-Expose-Headers", "X-Request-ID, X-Trace-ID")
		c.Header("Access-Control-Max-Age", "86400")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// LoggingMiddleware records request logs.
func LoggingMiddleware(log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()

		logFields := []logger.Field{
			logger.String("method", c.Request.Method),
			logger.String("path", c.Request.URL.Path),
			logger.Int("status", c.Writer.Status()),
			logger.Duration("latency", time.Since(start)),
			logger.String("client_ip", c.ClientIP()),
			logger.String("request_id", requestID),
		}
		if c.Writer.Status() >= 500 {
			log.Error(c.Request.Context(), "HTTP Server Error", nil, logFields...)
		} else {
			log.Info(c.Request.Context(), "HTTP Request", logFields...)
		}
	}
}

// RecoveryMiddleware recovers from panics.
func RecoveryMiddleware(log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				requestID, _ := c.Get("request_id")
				log.Error(c.Request.Context(), "Panic recovered", fmt.Errorf("%v", err),
					logger.String("stack", string(debug.Stack())),
					logger.Any("request_id", requestID),
				)
				response := dto.ErrorResponse(fmt.Errorf("%v", err), fmt.Sprintf("%v", requestID))
				c.JSON(http.StatusInternalServerError, response)
				c.Abort()
			}
		}()
		c.Next()
	}
}

// TracingMiddleware handles distributed tracing.
func TracingMiddleware(tracer trace.Tracer) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := tracer.Start(c.Request.Context(), fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path))
		defer span.End()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
		span.SetAttributes(attribute.Int("http.status_code", c.Writer.Status()))
		if c.Writer.Status() >= 400 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", c.Writer.Status()))
		}
	}
}

// RateLimitMiddleware enforces rate limits.
func RateLimitMiddleware(rateLimitService service.RateLimitService, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Simplified identifier for rate limiting
		identifier := c.ClientIP()
		dimension := service.RateLimitDimensionIP

		allowed, _, _, err := rateLimitService.Allow(c.Request.Context(), dimension, identifier, c.Request.URL.Path)
		if err != nil {
			log.Error(c.Request.Context(), "Rate limit check failed", err)
			c.Next() // Fail open
			return
		}
		if !allowed {
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, dto.ErrorResponse(errors.ErrRateLimitExceeded(string(dimension), 0), c.GetString("request_id")))
			c.Abort()
			return
		}
		c.Next()
	}
}

// AuthMiddleware validates JWTs and injects claims.
func AuthMiddleware(cryptoService service.CryptoService, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			respondUnauthorized(c, "MISSING_AUTHORIZATION_HEADER", "Authorization header is required")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			respondUnauthorized(c, "INVALID_AUTHORIZATION_FORMAT", "Authorization format must be Bearer <token>")
			return
		}
		tokenString := parts[1]

		// The tenant ID might be available in the request path or claims, but for simplicity, we pass an empty string.
		// A real implementation would need a strategy to determine the tenant context before verification.
		claims, err := cryptoService.VerifyJWT(c.Request.Context(), tokenString, "")
		if err != nil {
			log.Warn(c.Request.Context(), "JWT verification failed", logger.Error(err))
			respondUnauthorized(c, "AUTHENTICATION_FAILED", err.Error())
			return
		}

		// Inject claims into context
		if tenantID, ok := claims["tid"].(string); ok {
			c.Set("tenant_id", tenantID)
		}
		if agentID, ok := claims["sub"].(string); ok {
			c.Set("agent_id", agentID)
		}
		if scope, ok := claims["scp"].(string); ok {
			c.Set("scope", scope)
		}
		c.Set("claims", claims)
		c.Next()
	}
}

func respondUnauthorized(c *gin.Context, code, message string) {
	err := errors.ErrInvalidClient(message) // Using a standard error type
	if cbcErr, ok := err.(errors.CBCError); ok {
		cbcErr.WithMetadata("error_code", code)
	}
	c.JSON(http.StatusUnauthorized, dto.ErrorResponse(err, c.GetString("request_id")))
	c.Abort()
}

// SetupMiddlewares configures all middlewares for the router.
func SetupMiddlewares(router *gin.Engine, config *MiddlewareConfig) {
	router.Use(RecoveryMiddleware(config.Logger))
	router.Use(TracingMiddleware(config.Tracer))
	router.Use(LoggingMiddleware(config.Logger))
	router.Use(CORSMiddleware())
	router.Use(RateLimitMiddleware(config.RateLimitService, config.Logger))
	// AuthMiddleware is applied to specific routes, not globally.
}
