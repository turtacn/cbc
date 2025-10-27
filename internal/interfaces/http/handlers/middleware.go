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
	"github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// MiddlewareConfig 中间件配置
type MiddlewareConfig struct {
	RateLimitService service.RateLimitService
	JWTManager       crypto.JWTManager
	Logger           logger.Logger
	Tracer           trace.Tracer
}

// CORSMiddleware 处理跨域请求
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

// LoggingMiddleware 记录请求日志
func LoggingMiddleware(log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// 提取或生成 RequestID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		// 提取 TraceID
		traceID := c.GetHeader("X-Trace-ID")
		if traceID == "" {
			traceID = requestID
		}
		c.Set("trace_id", traceID)
		c.Header("X-Trace-ID", traceID)

		// 处理请求
		c.Next()

		// 计算延迟
		latency := time.Since(startTime)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// 记录日志
		logFields := []logger.Field{
			logger.String("method", method),
			logger.String("path", path),
			logger.Int("status", statusCode),
			logger.Int64("latency_ms", latency.Milliseconds()),
			logger.String("client_ip", clientIP),
			logger.String("user_agent", userAgent),
			logger.String("request_id", requestID),
			logger.String("trace_id", traceID),
		}

		if statusCode >= 500 {
			log.Error(c.Request.Context(), "HTTP request failed", nil, logFields...)
		} else if statusCode >= 400 {
			log.Warn(c.Request.Context(), "HTTP request error", logFields...)
		} else {
			log.Info(c.Request.Context(), "HTTP request completed", logFields...)
		}
	}
}

// RecoveryMiddleware 捕获 panic 并返回 500 错误
func RecoveryMiddleware(log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// 获取堆栈信息
				stack := string(debug.Stack())

				requestID, _ := c.Get("request_id")
				traceID, _ := c.Get("trace_id")

				// 记录错误日志
				log.Error(c.Request.Context(), "Panic recovered", fmt.Errorf("%v", err),
					logger.String("stack", stack),
					logger.Any("request_id", requestID),
					logger.Any("trace_id", traceID),
					logger.String("path", c.Request.URL.Path),
					logger.String("method", c.Request.Method),
				)

				// 返回标准错误响应
				response := dto.ErrorResponse(fmt.Errorf("%v", err), fmt.Sprintf("%v", traceID))

				c.JSON(http.StatusInternalServerError, response)
				c.Abort()
			}
		}()

		c.Next()
	}
}

// TracingMiddleware 创建分布式追踪 Span
func TracingMiddleware(tracer trace.Tracer) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从 Header 提取 TraceID
		traceID := c.GetHeader("X-Trace-ID")
		if traceID == "" {
			traceID = uuid.New().String()
			c.Set("trace_id", traceID)
		}

		// 创建 Span
		ctx, span := tracer.Start(c.Request.Context(), fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path))
		defer span.End()

		// 设置 Span 属性
		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.url", c.Request.URL.String()),
			attribute.String("http.client_ip", c.ClientIP()),
			attribute.String("trace_id", traceID),
		)

		// 将 Context 注入到 Gin Context
		c.Request = c.Request.WithContext(ctx)
		c.Set("span", span)

		// 处理请求
		c.Next()

		// 记录响应状态
		statusCode := c.Writer.Status()
		span.SetAttributes(attribute.Int("http.status_code", statusCode))

		if statusCode >= 400 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", statusCode))
		} else {
			span.SetStatus(codes.Ok, "")
		}
	}
}

// RateLimitMiddleware 执行速率限制
func RateLimitMiddleware(rateLimitService service.RateLimitService, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// 提取限流标识符（优先级：Agent ID > Tenant ID > IP）
		var identifier string
		var dimension service.RateLimitDimension

		// 从 JWT Token 中提取 AgentID 和 TenantID（如果已认证）
		if agentID, exists := c.Get("agent_id"); exists {
			identifier = fmt.Sprintf("%s", agentID)
			dimension = service.RateLimitDimensionDevice
		} else if tenantID, exists := c.Get("tenant_id"); exists {
			identifier = fmt.Sprintf("%s", tenantID)
			dimension = service.RateLimitDimensionTenant
		} else {
			identifier = c.ClientIP()
			dimension = service.RateLimitDimensionIP
		}

		// 检查限流
		allowed, _, _, err := rateLimitService.Allow(ctx, dimension, identifier, c.Request.URL.Path)
		if err != nil {
			log.Error(ctx, "Rate limit check failed", err,
				logger.String("identifier", identifier),
				logger.String("dimension", string(dimension)),
			)
			// 限流检查失败时，选择宽松策略（允许通过）
			c.Next()
			return
		}

		if !allowed {
			log.Warn(ctx, "Rate limit exceeded",
				logger.String("identifier", identifier),
				logger.String("dimension", string(dimension)),
				logger.String("path", c.Request.URL.Path),
			)

			response := dto.ErrorResponse(errors.ErrRateLimitExceeded(string(dimension), 0), c.GetString("trace_id"))

			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, response)
			c.Abort()
			return
		}

		c.Next()
	}
}

// AuthMiddleware 验证 JWT Token 并注入 Claims
func AuthMiddleware(jwtManager crypto.JWTManager, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// 提取 Authorization Header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			respondUnauthorized(c, "MISSING_AUTHORIZATION_HEADER", "Authorization header is required")
			return
		}

		// 验证格式：Bearer <token>
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			respondUnauthorized(c, "INVALID_AUTHORIZATION_FORMAT", "Authorization format must be: Bearer <token>")
			return
		}

		tokenString := parts[1]

		// 验证 JWT
		claims, err := jwtManager.VerifyJWT(ctx, tokenString)
		if err != nil {
			log.Warn(ctx, "JWT verification failed",
				logger.Error(err),
				logger.String("path", c.Request.URL.Path),
			)

			var errorCode, errorMsg string
			if cbcErr, ok := errors.AsCBCError(err); ok {
				errorCode = string(cbcErr.Code())
				errorMsg = cbcErr.Error()
			} else {
				errorCode = "AUTHENTICATION_FAILED"
				errorMsg = "Authentication failed"
			}

			respondUnauthorized(c, errorCode, errorMsg)
			return
		}

		// 注入 Claims 到 Context
		c.Set("claims", claims)
		c.Set("tenant_id", claims.TenantID)
		c.Set("agent_id", claims.Subject)
		c.Set("scope", claims.Scope)

		c.Next()
	}
}

// respondUnauthorized 返回 401 未授权错误
func respondUnauthorized(c *gin.Context, code, message string) {
	response := dto.ErrorResponse(errors.ErrInvalidClient(message), c.GetString("trace_id"))
	c.JSON(http.StatusUnauthorized, response)
	c.Abort()
}

// SetupMiddlewares 设置所有中间件（按顺序链式调用）
func SetupMiddlewares(router *gin.Engine, config *MiddlewareConfig) {
	// 1. Recovery (最先执行，捕获所有 panic)
	router.Use(RecoveryMiddleware(config.Logger))

	// 2. Tracing (创建追踪 Span)
	router.Use(TracingMiddleware(config.Tracer))

	// 3. Logging (记录请求日志)
	router.Use(LoggingMiddleware(config.Logger))

	// 4. CORS (处理跨域)
	router.Use(CORSMiddleware())

	// 5. RateLimit (速率限制，在认证之前)
	router.Use(RateLimitMiddleware(config.RateLimitService, config.Logger))

	// 注意：AuthMiddleware 不在全局应用，只在需要认证的路由组中使用
}
