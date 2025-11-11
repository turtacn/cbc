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

// HealthHandler provides HTTP handlers for Kubernetes liveness and readiness probes.
// HealthHandler 为 Kubernetes 的活性和就绪性探针提供 HTTP 处理器。
type HealthHandler struct {
	dbConn    *postgres.DBConnection
	redisConn redis.RedisConnectionManager
	logger    logger.Logger
}

// NewHealthHandler creates a new HealthHandler with dependencies for checking the health of external services.
// NewHealthHandler 使用用于检查外部服务健康状况的依赖项创建一个新的 HealthHandler。
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

// HealthResponse defines the structure of the JSON response for health checks.
// HealthResponse 定义了健康检查的 JSON 响应的结构。
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

// ReadinessCheck is the handler for the readiness probe (e.g., /ready).
// It performs a deep check of all critical dependencies like the database and Redis.
// The service is considered "ready" only if all dependencies are healthy.
// GET /ready
// ReadinessCheck 是就绪性探针的处理程序（例如 /ready）。
// 它对所有关键依赖项（如数据库和 Redis）执行深度检查。
// 只有当所有依赖项都健康时，该服务才被视为“就绪”。
func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	checks := make(map[string]string)
	allReady := true

	// Check all critical dependencies.
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

// LivenessCheck is the handler for the liveness probe (e.g., /live).
// This is a shallow check that simply confirms the HTTP server is running and responsive.
// GET /live
// LivenessCheck 是活性探针的处理程序（例如 /live）。
// 这是一个浅层检查，仅确认 HTTP 服务器正在运行并响应。
func (h *HealthHandler) LivenessCheck(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{
		Status:    "alive",
		Timestamp: time.Now().UTC(),
	})
}

// checkDatabase performs a health check on the database connection.
// checkDatabase 对数据库连接执行健康检查。
func (h *HealthHandler) checkDatabase(ctx context.Context) error {
	if h.dbConn == nil {
		return fmt.Errorf("database connection is nil")
	}
	return h.dbConn.Ping(ctx)
}

// checkRedis performs a health check on the Redis connection.
// checkRedis 对 Redis 连接执行健康检查。
func (h *HealthHandler) checkRedis(ctx context.Context) error {
	if h.redisConn == nil {
		return fmt.Errorf("redis connection manager is nil")
	}
	client := h.redisConn.GetClient()
	if client == nil {
		return fmt.Errorf("redis client is nil")
	}

	// Execute a PING command to verify the connection.
	return client.Ping(ctx).Err()
}
