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

// MiddlewareConfig holds the dependencies required by the various middleware functions.
// This struct is used to inject services like logging, rate limiting, and tracing into the middleware chain.
// MiddlewareConfig 保存各种中间件功能所需的依赖项。
// 此结构用于将日志记录、速率限制和跟踪等服务注入到中间件链中。
type MiddlewareConfig struct {
	RateLimitService service.RateLimitService
	KMS              service.KeyManagementService
	Logger           logger.Logger
	Tracer           trace.Tracer
}

// CORSMiddleware returns a Gin middleware handler for Cross-Origin Resource Sharing (CORS).
// It sets permissive headers suitable for development and testing. For production, these should be more restrictive.
// CORSMiddleware 返回一个用于跨域资源共享 (CORS) 的 Gin 中间件处理程序。
// 它设置了适用于开发和测试的宽松标头。对于生产环境，这些应该更严格。
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-Trace-ID")
		c.Header("Access-Control-Expose-Headers", "X-Request-ID, X-Trace-ID")
		c.Header("Access-Control-Max-Age", "86400") // 24 hours
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// LoggingMiddleware returns a Gin middleware handler that logs every incoming HTTP request.
// It injects a request ID and logs key information like method, path, status, and latency.
// LoggingMiddleware 返回一个记录每个传入 HTTP 请求的 Gin 中间件处理程序。
// 它注入一个请求 ID 并记录关键信息，如方法、路径、状态和延迟。
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

// RecoveryMiddleware returns a Gin middleware handler that recovers from any panics in downstream handlers.
// It logs the panic with a stack trace and returns a 500 Internal Server Error response.
// RecoveryMiddleware 返回一个从下游处理程序中的任何紧急情况中恢复的 Gin 中间件处理程序。
// 它使用堆栈跟踪记录紧急情况，并返回 500 内部服务器错误响应。
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

// TracingMiddleware returns a Gin middleware handler for integrating with OpenTelemetry distributed tracing.
// It starts a new span for each request and adds HTTP-related attributes.
// TracingMiddleware 返回一个用于与 OpenTelemetry 分布式跟踪集成的 Gin 中间件处理程序。
// 它为每个请求启动一个新的跨度，并添加与 HTTP 相关的属性。
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

// RateLimitMiddleware returns a Gin middleware that enforces rate limits based on client IP.
// It checks with the rate limiting service and returns a 429 Too Many Requests if the limit is exceeded.
// RateLimitMiddleware 返回一个基于客户端 IP 强制执行速率限制的 Gin 中间件。
// 它会与速率限制服务进行核对，如果超出限制，则返回 429 Too Many Requests。
func RateLimitMiddleware(rateLimitService service.RateLimitService, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use client IP as the primary identifier for rate limiting.
		identifier := c.ClientIP()
		dimension := service.RateLimitDimensionIP

		allowed, _, _, err := rateLimitService.Allow(c.Request.Context(), dimension, identifier, c.Request.URL.Path)
		if err != nil {
			log.Error(c.Request.Context(), "Rate limit check failed", err)
			c.Next() // Fail open to avoid blocking users if the rate limiter is down.
			return
		}
		if !allowed {
			c.Header("Retry-After", "60") // Inform the client to wait for 60 seconds.
			c.JSON(http.StatusTooManyRequests, dto.ErrorResponse(errors.ErrRateLimitExceeded(string(dimension), 0), c.GetString("request_id")))
			c.Abort()
			return
		}
		c.Next()
	}
}

// AuthMiddleware returns a Gin middleware that validates a JWT from the Authorization header.
// If valid, it extracts claims and injects them into the request context for downstream handlers.
// AuthMiddleware 返回一个 Gin 中间件，用于验证来自 Authorization 标头的 JWT。
// 如果有效，它会提取声明并将其注入到请求上下文中以供下游处理程序使用。
func AuthMiddleware(kms service.KeyManagementService, log logger.Logger) gin.HandlerFunc {
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

		// Verify the JWT. A real implementation would need a strategy to determine the tenant context
		// (e.g., from a path parameter or a claim) before verification.
		claims, err := kms.VerifyJWT(c.Request.Context(), tokenString, "")
		if err != nil {
			log.Warn(c.Request.Context(), "JWT verification failed", logger.Error(err))
			respondUnauthorized(c, "AUTHENTICATION_FAILED", err.Error())
			return
		}

		// Inject key claims into the context for easy access in handlers.
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

// respondUnauthorized is a helper function to send a standardized 401 Unauthorized response.
// respondUnauthorized 是一个辅助函数，用于发送标准化的 401 未授权响应。
func respondUnauthorized(c *gin.Context, code, message string) {
	err := errors.ErrInvalidClient(message)
	if cbcErr, ok := err.(errors.CBCError); ok {
		cbcErr.WithMetadata("error_code", code)
	}
	c.JSON(http.StatusUnauthorized, dto.ErrorResponse(err, c.GetString("request_id")))
	c.Abort()
}

// SetupMiddlewares configures and applies all global middlewares to the Gin router.
// The order of middleware is important for correct execution flow.
// SetupMiddlewares 配置并将所有全局中间件应用于 Gin 路由器。
// 中间件的顺序对于正确的执行流程很重要。
func SetupMiddlewares(router *gin.Engine, config *MiddlewareConfig) {
	// The order of middleware matters. Recovery should be first to catch panics from any other middleware.
	router.Use(RecoveryMiddleware(config.Logger))
	router.Use(TracingMiddleware(config.Tracer))
	router.Use(LoggingMiddleware(config.Logger))
	router.Use(CORSMiddleware())
	router.Use(RateLimitMiddleware(config.RateLimitService, config.Logger))
	// Note: AuthMiddleware is not applied globally as some routes may be public.
	// It should be applied to specific route groups that require authentication.
}
