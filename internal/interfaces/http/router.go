package http

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/pkg/logger"
)

// RouterDependencies holds all dependencies for the router.
type RouterDependencies struct {
	Config         *config.ServerConfig
	Logger         logger.Logger
	AuthHandler    *handlers.AuthHandler
	DeviceHandler  *handlers.DeviceHandler
	HealthHandler  *handlers.HealthHandler
	Middleware     []gin.HandlerFunc
}

// NewRouter creates and configures a new Gin router.
func NewRouter(deps RouterDependencies) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Register global middleware
	for _, mw := range deps.Middleware {
		router.Use(mw)
	}

	// Health checks
	router.GET("/health", deps.HealthHandler.HealthCheck)
	router.GET("/ready", deps.HealthHandler.ReadinessCheck)

	// Metrics
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/token", deps.AuthHandler.IssueToken)
			auth.POST("/refresh", deps.AuthHandler.RefreshToken)
			auth.POST("/revoke", deps.AuthHandler.RevokeToken)
			auth.GET("/jwks/:tenant_id", deps.AuthHandler.GetJWKS)
		}
		devices := v1.Group("/devices")
		{
			// These would typically be protected by an auth middleware
			devices.POST("", deps.DeviceHandler.RegisterDevice)
			devices.GET("/:device_id", deps.DeviceHandler.GetDevice)
			devices.PUT("/:device_id", deps.DeviceHandler.UpdateDevice)
		}
	}

	return router
}

// StartServer starts the HTTP server and handles graceful shutdown.
func StartServer(router *gin.Engine, cfg *config.ServerConfig, log logger.Logger) {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(context.Background(), "Failed to start HTTP server", err)
		}
	}()

	log.Info(context.Background(), fmt.Sprintf("HTTP server listening on :%d", cfg.Port))

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info(context.Background(), "Shutting down HTTP server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error(context.Background(), "HTTP server shutdown failed", err)
	} else {
		log.Info(context.Background(), "HTTP server gracefully stopped")
	}
}
//Personal.AI order the ending