package http

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/internal/interfaces/http/middleware"
	"github.com/turtacn/cbc/pkg/logger"
)

// Router encapsulates the Gin engine and all HTTP handlers and middleware for the main public-facing API.
// It is responsible for setting up routes, starting the server, and handling graceful shutdown.
// Router 封装了 Gin 引擎以及主面向公众 API 的所有 HTTP 处理程序和中间件。
// 它负责设置路由、启动服务器和处理正常关闭。
type Router struct {
	engine                  *gin.Engine
	config                  *config.Config
	logger                  logger.Logger
	healthHandler           *handlers.HealthHandler
	authHandler             *handlers.AuthHandler
	oauthHandler            *handlers.OAuthHandler
	deviceHandler           *handlers.DeviceHandler
	jwksHandler             *handlers.JWKSHandler
	authMiddleware          gin.HandlerFunc
	rateLimitMiddleware     gin.HandlerFunc
	idempotencyMiddleware   gin.HandlerFunc
	observabilityMiddleware gin.HandlerFunc
	server                  *http.Server
}

// NewRouter creates and configures a new Router instance with all its dependencies.
// NewRouter 创建并配置一个新的 Router 实例及其所有依赖项。
func NewRouter(
	cfg *config.Config,
	log logger.Logger,
	healthHandler *handlers.HealthHandler,
	authHandler *handlers.AuthHandler,
	deviceHandler *handlers.DeviceHandler,
	jwksHandler *handlers.JWKSHandler,
	oauthHandler *handlers.OAuthHandler,
	authMiddleware gin.HandlerFunc,
	rateLimitMiddleware gin.HandlerFunc,
	idempotencyMiddleware gin.HandlerFunc,
	observabilityMiddleware gin.HandlerFunc,
) *Router {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	return &Router{
		engine:                  engine,
		config:                  cfg,
		logger:                  log,
		healthHandler:           healthHandler,
		authHandler:             authHandler,
		oauthHandler:            oauthHandler,
		deviceHandler:           deviceHandler,
		jwksHandler:             jwksHandler,
		authMiddleware:          authMiddleware,
		rateLimitMiddleware:     rateLimitMiddleware,
		idempotencyMiddleware:   idempotencyMiddleware,
		observabilityMiddleware: observabilityMiddleware,
	}
}

// SetupRoutes configures all the middleware and API endpoints for the main router.
// SetupRoutes 为主路由器配置所有中间件和 API 端点。
func (r *Router) SetupRoutes() {
	// Apply global middleware.
	r.engine.Use(gin.Recovery())
	r.engine.Use(r.observabilityMiddleware)

	// Configure CORS.
	corsConfig := cors.Config{
		AllowOrigins:     []string{"*"}, // Should be restricted in production
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	r.engine.Use(cors.New(corsConfig))

	// Public routes (health checks, metrics).
	r.engine.GET("/health/live", r.healthHandler.LivenessCheck)
	r.engine.GET("/health/ready", r.healthHandler.ReadinessCheck)
	r.engine.GET("/live", r.healthHandler.LivenessCheck)
	r.engine.GET("/ready", r.healthHandler.ReadinessCheck)
	r.engine.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Pprof profiling routes (enabled only in non-production environments).
	if r.config.Observability.PprofEnabled {
		pprof.Register(r.engine)
	}

	// API v1 route group with shared middleware.
	v1 := r.engine.Group("/api/v1")
	v1.Use(r.idempotencyMiddleware)
	v1.Use(r.rateLimitMiddleware)
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/token", r.authHandler.IssueToken)
			auth.POST("/refresh", r.authHandler.RefreshToken)
			auth.POST("/revoke", r.authHandler.RevokeToken)
			auth.GET("/jwks/:tenant_id", middleware.ETagCache(), r.jwksHandler.GetJWKS)
		}
		oauth := v1.Group("/oauth")
		{
			oauth.POST("/device_authorization", r.oauthHandler.StartDeviceAuthorization)
			// Dev-only endpoint for simulating user verification.
			if r.config.OAuth.DevVerifyAPIEnabled {
				oauth.POST("/verify", r.oauthHandler.VerifyUserCode)
			}
		}
		// Device routes require authentication.
		devices := v1.Group("/devices")
		devices.Use(r.authMiddleware)
		{
			devices.POST("", r.deviceHandler.RegisterDevice)
			devices.GET("/:device_id", r.deviceHandler.GetDevice)
			devices.PUT("/:device_id", r.deviceHandler.UpdateDevice)
		}
	}

	// Custom 404 Not Found handler.
	r.engine.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "The requested resource was not found",
		})
	})
}

// Start initializes and starts the HTTP server.
// It also sets up a graceful shutdown mechanism.
// Start 初始化并启动 HTTP 服务器。
// 它还设置了正常关闭机制。
func (r *Router) Start() error {
	r.SetupRoutes()

	addr := fmt.Sprintf("%s:%d", r.config.Server.HTTPHost, r.config.Server.HTTPPort)
	r.server = &http.Server{
		Addr:           addr,
		Handler:        r.engine,
		ReadTimeout:    r.config.Server.HTTPReadTimeout,
		WriteTimeout:   r.config.Server.HTTPWriteTimeout,
		IdleTimeout:    r.config.Server.HTTPIdleTimeout,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	r.logger.Info(context.Background(), "Starting main HTTP server", logger.String("address", addr))

	// Run the graceful shutdown handler in a separate goroutine.
	go r.gracefulShutdown()

	if err := r.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		r.logger.Error(context.Background(), "HTTP server failed to start", err)
		return err
	}

	return nil
}

// gracefulShutdown listens for termination signals (SIGINT, SIGTERM) and gracefully shuts down the server.
// gracefulShutdown 侦听终止信号 (SIGINT, SIGTERM) 并正常关闭服务器。
func (r *Router) gracefulShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	r.logger.Info(context.Background(), "Shutting down HTTP server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := r.server.Shutdown(ctx); err != nil {
		r.logger.Error(context.Background(), "Server forced to shutdown due to error", err)
	}

	r.logger.Info(context.Background(), "HTTP server stopped gracefully")
}

// Stop gracefully stops the HTTP server.
// Stop 正常停止 HTTP 服务器。
func (r *Router) Stop(ctx context.Context) error {
	if r.server == nil {
		return nil
	}
	r.logger.Info(ctx, "Stopping HTTP server...")
	return r.server.Shutdown(ctx)
}

// Engine returns the underlying Gin engine, useful for testing.
// Engine 返回底层的 Gin 引擎，可用于测试。
func (r *Router) Engine() *gin.Engine {
	return r.engine
}

// InternalRouter encapsulates the Gin engine and handlers for the internal-only API.
// This router runs on a separate port and is not exposed to the public.
// InternalRouter 封装了仅供内部使用的 API 的 Gin 引擎和处理程序。
// 该路由器在单独的端口上运行，不对公众公开。
type InternalRouter struct {
	engine          *gin.Engine
	mlInternalHandler *handlers.MLInternalHandler
}

// NewInternalRouter creates a new instance of the InternalRouter.
// NewInternalRouter 创建一个新的 InternalRouter 实例。
func NewInternalRouter(mlInternalHandler *handlers.MLInternalHandler) *InternalRouter {
	engine := gin.New()
	engine.Use(gin.Recovery()) // Use a basic recovery middleware.
	return &InternalRouter{
		engine:          engine,
		mlInternalHandler: mlInternalHandler,
	}
}

// SetupRoutes configures the routes for the internal-only API.
// SetupRoutes 配置仅供内部使用的 API 的路由。
func (r *InternalRouter) SetupRoutes() {
	internal := r.engine.Group("/_internal")
	{
		ml := internal.Group("/ml")
		{
			ml.POST("/risk", r.mlInternalHandler.UpdateTenantRisk)
		}
	}
}

// Engine returns the underlying Gin engine for the internal router.
// Engine 返回内部路由器的底层 Gin 引擎。
func (r *InternalRouter) Engine() *gin.Engine {
	return r.engine
}
