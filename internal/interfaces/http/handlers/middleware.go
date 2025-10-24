package handlers

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"cbc-auth-service/internal/application/dto"
	"cbc-auth-service/internal/domain/service"
	"cbc-auth-service/internal/infrastructure/crypto"
	"cbc-auth-service/pkg/errors"
	"cbc-auth-service/pkg/logger"
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
		fields := map[string]interface{}{
			"method":      method,
			"path":        path,
			"status":      statusCode,
			"latency_ms":  latency.Milliseconds(),
			"client_ip":   clientIP,
			"user_agent":  userAgent,
			"request_id":  requestID,
			"trace_id":    traceID,
		}

		if statusCode >= 500 {
			log.Error("HTTP request failed", fields)
		} else if statusCode >= 400 {
			log.Warn("HTTP request error", fields)
		} else {
			log.Info("HTTP request completed", fields)
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
				log.Error("Panic recovered", map[string]interface{}{
					"error":      fmt.Sprintf("%v", err),
					"stack":      stack,
					"request_id": requestID,
					"trace_id":   traceID,
					"path":       c.Request.URL.Path,
					"method":     c.Request.Method,
				})

				// 返回标准错误响应
				response := dto.ErrorResponse{
					Success: false,
					Error: &dto.ErrorDetail{
						Code:    "INTERNAL_SERVER_ERROR",
						Message: "An internal server error occurred",
					},
					RequestID: fmt.Sprintf("%v", requestID),
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				}

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
			trace.WithAttributes(
				trace.StringAttribute("http.method", c.Request.Method),
				trace.StringAttribute("http.url", c.Request.URL.String()),
				trace.StringAttribute("http.client_ip", c.ClientIP()),
				trace.StringAttribute("trace_id", traceID),
			)...,
		)

		// 将 Context 注入到 Gin Context
		c.Request = c.Request.WithContext(ctx)
		c.Set("span", span)

		// 处理请求
		c.Next()

		// 记录响应状态
		statusCode := c.Writer.Status()
		span.SetAttributes(trace.IntAttribute("http.status_code", statusCode))

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
		var scope string

		// 从 JWT Token 中提取 AgentID 和 TenantID（如果已认证）
		if agentID, exists := c.Get("agent_id"); exists {
			identifier = fmt.Sprintf("agent:%s", agentID)
			scope = "agent"
		} else if tenantID, exists := c.Get("tenant_id"); exists {
			identifier = fmt.Sprintf("tenant:%s", tenantID)
			scope = "tenant"
		} else {
			identifier = fmt.Sprintf("ip:%s", c.ClientIP())
			scope = "global"
		}

		// 检查限流
		allowed, err := rateLimitService.CheckRateLimit(ctx, identifier, scope)
		if err != nil {
			log.Error("Rate limit check failed", map[string]interface{}{
				"error":      err.Error(),
				"identifier": identifier,
				"scope":      scope,
			})
			// 限流检查失败时，选择宽松策略（允许通过）
			c.Next()
			return
		}

		if !allowed {
			log.Warn("Rate limit exceeded", map[string]interface{}{
				"identifier": identifier,
				"scope":      scope,
				"path":       c.Request.URL.Path,
			})

			response := dto.ErrorResponse{
				Success: false,
				Error: &dto.ErrorDetail{
					Code:    "RATE_LIMIT_EXCEEDED",
					Message: "Too many requests, please try again later",
				},
				RequestID: c.GetString("request_id"),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}

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
			log.Warn("JWT verification failed", map[string]interface{}{
				"error": err.Error(),
				"path":  c.Request.URL.Path,
			})

			var errorCode, errorMsg string
			switch {
			case errors.IsTokenExpiredError(err):
				errorCode = "TOKEN_EXPIRED"
				errorMsg = "Token has expired"
			case errors.IsTokenInvalidError(err):
				errorCode = "INVALID_TOKEN"
				errorMsg = "Token is invalid"
			default:
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
	response := dto.ErrorResponse{
		Success: false,
		Error: &dto.ErrorDetail{
			Code:    code,
			Message: message,
		},
		RequestID: c.GetString("request_id"),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

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

//Personal.AI order the ending
