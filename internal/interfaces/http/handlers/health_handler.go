package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/pkg/logger"
)

// HealthHandler 健康检查处理器
type HealthHandler struct {
	dbConn      *postgres.DBConnection
	redisConn   *redis.RedisConnection
	vaultClient *crypto.VaultClient
	logger      logger.Logger
}

// NewHealthHandler 创建健康检查处理器
func NewHealthHandler(
	dbConn *postgres.DBConnection,
	redisConn *redis.RedisConnection,
	vaultClient *crypto.VaultClient,
	log logger.Logger,
) *HealthHandler {
	return &HealthHandler{
		dbConn:      dbConn,
		redisConn:   redisConn,
		vaultClient: vaultClient,
		logger:      log,
	}
}

// HealthResponse 健康检查响应
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]string `json:"checks"`
}

// HealthCheck 健康检查端点
// GET /health
func (h *HealthHandler) HealthCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	checks := make(map[string]string)
	allHealthy := true

	// 检查数据库连接
	if err := h.checkDatabase(ctx); err != nil {
		checks["database"] = "unhealthy: " + err.Error()
		allHealthy = false
		h.logger.Error(ctx, "Database health check failed", err)
	} else {
		checks["database"] = "ok"
	}

	// 检查 Redis 连接
	if err := h.checkRedis(ctx); err != nil {
		checks["redis"] = "unhealthy: " + err.Error()
		allHealthy = false
		h.logger.Error(ctx, "Redis health check failed", err)
	} else {
		checks["redis"] = "ok"
	}

	// 检查 Vault 连接
	if err := h.checkVault(ctx); err != nil {
		checks["vault"] = "unhealthy: " + err.Error()
		allHealthy = false
		h.logger.Error(ctx, "Vault health check failed", err)
	} else {
		checks["vault"] = "ok"
	}

	status := "healthy"
	httpStatus := http.StatusOK
	if !allHealthy {
		status = "unhealthy"
		httpStatus = http.StatusServiceUnavailable
	}

	response := HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC(),
		Checks:    checks,
	}

	c.JSON(httpStatus, response)
}

// ReadinessCheck 就绪检查端点
// GET /ready
func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	checks := make(map[string]string)
	allReady := true

	// 检查所有依赖是否可用
	if err := h.checkDatabase(ctx); err != nil {
		checks["database"] = "not ready"
		allReady = false
	} else {
		checks["database"] = "ready"
	}

	if err := h.checkRedis(ctx); err != nil {
		checks["redis"] = "not ready"
		allReady = false
	} else {
		checks["redis"] = "ready"
	}

	if err := h.checkVault(ctx); err != nil {
		checks["vault"] = "not ready"
		allReady = false
	} else {
		checks["vault"] = "ready"
	}

	status := "ready"
	httpStatus := http.StatusOK
	if !allReady {
		status = "not ready"
		httpStatus = http.StatusServiceUnavailable
	}

	response := HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC(),
		Checks:    checks,
	}

	c.JSON(httpStatus, response)
}

// LivenessCheck 存活检查端点
// GET /live
func (h *HealthHandler) LivenessCheck(c *gin.Context) {
	// 简单的存活检查，只要服务能响应就表示存活
	c.JSON(http.StatusOK, gin.H{
		"status":    "alive",
		"timestamp": time.Now().UTC(),
	})
}

// checkDatabase 检查数据库连接
func (h *HealthHandler) checkDatabase(ctx context.Context) error {
	if h.dbConn == nil {
		return fmt.Errorf("database connection is nil")
	}

	return h.dbConn.Ping(ctx)
}

// checkRedis 检查 Redis 连接
func (h *HealthHandler) checkRedis(ctx context.Context) error {
	client := h.redisConn.GetClient()
	if client == nil {
		return fmt.Errorf("redis client is nil")
	}

	// 执行 PING 命令验证连接
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return err
	}

	return nil
}

// checkVault 检查 Vault 连接
func (h *HealthHandler) checkVault(ctx context.Context) error {
	if h.vaultClient == nil {
		return fmt.Errorf("vault client is nil")
	}

	// 检查 Vault 健康状态
	healthy, err := h.vaultClient.Health(ctx)
	if err != nil {
		return err
	}

	if !healthy {
		return fmt.Errorf("vault is not healthy")
	}

	return nil
}
