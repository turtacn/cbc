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
	server         *http.Server
}

// NewRouter 创建路由器
func NewRouter(
	cfg *config.Config,
	log logger.Logger,
	healthHandler *handlers.HealthHandler,
	authHandler *handlers.AuthHandler,
	deviceHandler *handlers.DeviceHandler,
) *Router {
	// 设置 Gin 模式
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	return &Router{
		engine:         engine,
		config:         cfg,
		logger:         log,
		healthHandler:  healthHandler,
		authHandler:    authHandler,
		deviceHandler:  deviceHandler,
	}
}

// SetupRoutes 设置路由
func (r *Router) SetupRoutes() {
	// 全局中间件
	r.engine.Use(gin.Recovery())

	// CORS 配置
	corsConfig := cors.Config{
		AllowOrigins:     []string{"*"},
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
	if r.config.Monitoring.PprofEnabled {
		pprof.Register(r.engine)
	}

	// API 路由组
	v1 := r.engine.Group("/api/v1")
	{
		// 认证相关路由
		auth := v1.Group("/auth")
		{
			auth.POST("/token", r.authHandler.IssueToken)
		}

		// 设备相关路由（需要认证）
		devices := v1.Group("/devices")
		{
			devices.POST("", r.deviceHandler.RegisterDevice)
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

	addr := fmt.Sprintf("%s:%d", r.config.Server.HTTPHost, r.config.Server.HTTPPort)
	r.server = &http.Server{
		Addr:           addr,
		Handler:        r.engine,
		ReadTimeout:    r.config.Server.HTTPReadTimeout,
		WriteTimeout:   r.config.Server.HTTPWriteTimeout,
		IdleTimeout:    r.config.Server.HTTPIdleTimeout,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	r.logger.Info(context.Background(), "Starting HTTP server", logger.String("address", addr))

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

	r.logger.Info(context.Background(), "Shutting down HTTP server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := r.server.Shutdown(ctx); err != nil {
		r.logger.Error(context.Background(), "Server forced to shutdown", err)
	}

	r.logger.Info(context.Background(), "HTTP server stopped")
}

// Stop 停止 HTTP 服务器
func (r *Router) Stop(ctx context.Context) error {
	if r.server == nil {
		return nil
	}

	r.logger.Info(ctx, "Stopping HTTP server...")
	return r.server.Shutdown(ctx)
}
