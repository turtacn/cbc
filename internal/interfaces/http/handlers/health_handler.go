package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/pkg/logger"
)

// HealthHandler 健康检查处理器
type HealthHandler struct {
	dbConn    *postgres.DBConnection
	redisConn redis.RedisConnectionManager
	logger    logger.Logger
}

// NewHealthHandler 创建健康检查处理器
func NewHealthHandler(
	dbConn *postgres.DBConnection,
	redisConn redis.RedisConnectionManager,
	log logger.Logger,
) *HealthHandler {
	return &HealthHandler{
		dbConn:    dbConn,
		redisConn: redisConn,
		logger:    log,
	}
}

// HealthResponse 健康检查响应
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]string `json:"checks"`
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
