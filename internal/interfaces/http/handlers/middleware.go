package handlers

import (
	goerrors "errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
)

// CORSMiddleware handles cross-origin resource sharing.
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

// LoggingMiddleware logs incoming requests.
func LoggingMiddleware(log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		log.Info(c.Request.Context(), "Request processed", logger.Fields{
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"status":     c.Writer.Status(),
			"latency_ms": latency.Milliseconds(),
			"client_ip":  c.ClientIP(),
		})
	}
}

// RecoveryMiddleware recovers from panics.
func RecoveryMiddleware(log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Error(c.Request.Context(), "Panic recovered", goerrors.New("panic"), logger.Fields{"panic": err})
				dto.SendError(c, errors.ErrInternalServer)
			}
		}()
		c.Next()
	}
}

// TracingMiddleware adds tracing to requests.
func TracingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract trace context from headers
		propagator := propagation.TraceContext{}
		ctx := propagator.Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))

		ctx, span := monitoring.StartSpan(
			ctx,
			"HTTP "+c.Request.Method,
			trace.WithAttributes(
				semconv.HTTPMethodKey.String(c.Request.Method),
				semconv.HTTPURLKey.String(c.Request.URL.String()),
			),
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		traceID := span.SpanContext().TraceID().String()
		c.Set("trace_id", traceID)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// RateLimitMiddleware applies rate limiting to requests.
func RateLimitMiddleware(limiter service.RateLimitService) gin.HandlerFunc {
	return func(c *gin.Context) {
		allowed, err := limiter.Allow(c.Request.Context(), constants.RateLimitScopeIP, c.ClientIP())
		if err != nil {
			dto.SendError(c, err)
			c.Abort()
			return
		}
		if !allowed {
			dto.SendError(c, errors.ErrRateLimitExceeded)
			c.Abort()
			return
		}
		c.Next()
	}
}

// AuthMiddleware validates JWTs for protected endpoints.
func AuthMiddleware(cryptoSvc service.CryptoService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		tokenString := ""
		if _, err := fmt.Sscanf(authHeader, "Bearer %s", &tokenString); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			return
		}

		// This is a simplified implementation. A real one would get the tenant ID from the token first.
		tenantID := uuid.New()
		claims, err := cryptoSvc.VerifyJWT(c.Request.Context(), tokenString, tenantID)
		if err != nil {
			dto.SendError(c, err)
			c.Abort()
			return
		}
		c.Set(string(constants.ContextKeyClaims), claims)
		c.Next()
	}
}

//Personal.AI order the ending
