package http

import (
	"context"
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
	"github.com/turtacn/cbc/pkg/logger"
)

// Router HTTP 路由器
type Router struct {
	engine         *gin.Engine
	config         *config.Config
	logger         logger.Logger
	healthHandler  *handlers.HealthHandler
	authHandler    *handlers.AuthHandler
	deviceHandler  *handlers.DeviceHandler
	middleware     *handlers.Middleware
	server         *http.Server
}

// NewRouter 创建路由器
func NewRouter(
	cfg *config.Config,
	log logger.Logger,
	healthHandler *handlers.HealthHandler,
	authHandler *handlers.AuthHandler,
	deviceHandler *handlers.DeviceHandler,
	middleware *handlers.Middleware,
) *Router {
	// 设置 Gin 模式
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()

	return &Router{
		engine:         engine,
		config:         cfg,
		logger:         log,
		healthHandler:  healthHandler,
		authHandler:    authHandler,
		deviceHandler:  deviceHandler,
		middleware:     middleware,
	}
}

// SetupRoutes 设置路由
func (r *Router) SetupRoutes() {
	// 全局中间件
	r.engine.Use(gin.Recovery())
	r.engine.Use(r.middleware.Logger())
	r.engine.Use(r.middleware.RequestID())
	r.engine.Use(r.middleware.Metrics())

	// CORS 配置
	corsConfig := cors.Config{
		AllowOrigins:     r.config.Server.AllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	r.engine.Use(cors.New(corsConfig))

	// 健康检查路由（不需要认证）
	r.engine.GET("/health", r.healthHandler.HealthCheck)
	r.engine.GET("/ready", r.healthHandler.ReadinessCheck)
	r.engine.GET("/live", r.healthHandler.LivenessCheck)

	// Prometheus metrics
	r.engine.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Pprof 性能分析（仅在非生产环境）
	if r.config.Server.Environment != "production" {
		pprof.Register(r.engine)
	}

	// API 路由组
	v1 := r.engine.Group("/api/v1")
	{
		// 认证相关路由
		auth := v1.Group("/auth")
		{
			auth.POST("/token", r.authHandler.IssueToken)
			auth.POST("/refresh", r.authHandler.RefreshToken)
			auth.POST("/revoke", r.middleware.Authenticate(), r.authHandler.RevokeToken)
			auth.GET("/jwks/:tenant_id", r.authHandler.GetPublicKeys)
			auth.POST("/introspect", r.authHandler.IntrospectToken)
		}

		// 设备相关路由（需要认证）
		devices := v1.Group("/devices")
		devices.Use(r.middleware.Authenticate())
		{
			devices.POST("", r.deviceHandler.RegisterDevice)
			devices.GET("", r.deviceHandler.ListDevices)
			devices.GET("/:device_id", r.deviceHandler.GetDeviceInfo)
			devices.PUT("/:device_id", r.deviceHandler.UpdateDeviceInfo)
		}
	}

	// 404 处理
	r.engine.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "The requested resource was not found",
		})
	})
}

// Start 启动 HTTP 服务器
func (r *Router) Start() error {
	r.SetupRoutes()

	addr := r.config.Server.HTTPAddress
	r.server = &http.Server{
		Addr:           addr,
		Handler:        r.engine,
		ReadTimeout:    time.Duration(r.config.Server.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(r.config.Server.WriteTimeout) * time.Second,
		IdleTimeout:    time.Duration(r.config.Server.IdleTimeout) * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	r.logger.Info("Starting HTTP server", "address", addr)

	// 优雅关闭
	go r.gracefulShutdown()

	if err := r.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

// gracefulShutdown 优雅关闭服务器
func (r *Router) gracefulShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	r.logger.Info("Shutting down HTTP server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := r.server.Shutdown(ctx); err != nil {
		r.logger.Error("Server forced to shutdown", "error", err)
	}

	r.logger.Info("HTTP server stopped")
}

// Stop 停止 HTTP 服务器
func (r *Router) Stop(ctx context.Context) error {
	if r.server == nil {
		return nil
	}

	r.logger.Info("Stopping HTTP server...")
	return r.server.Shutdown(ctx)
}

//Personal.AI order the ending
