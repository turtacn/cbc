package handlers

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/pkg/logger"
)

// HealthHandler provides health check endpoints.
type HealthHandler struct {
	db    *postgres.DBConnection
	redis *redis.RedisConnection
	vault crypto.VaultClient
	log   logger.Logger
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(db *postgres.DBConnection, redis *redis.RedisConnection, vault crypto.VaultClient, log logger.Logger) *HealthHandler {
	return &HealthHandler{
		db:    db,
		redis: redis,
		vault: vault,
		log:   log,
	}
}

// HealthCheck godoc
// @Summary      Health Check
// @Description  Checks the health of the service and its dependencies.
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      503  {object}  map[string]interface{}
// @Router       /health [get]
func (h *HealthHandler) HealthCheck(c *gin.Context) {
	status := "healthy"
	checks := h.performChecks()

	httpStatus := http.StatusOK
	for _, checkStatus := range checks {
		if checkStatus != "ok" {
			status = "unhealthy"
			httpStatus = http.StatusServiceUnavailable
			break
		}
	}

	c.JSON(httpStatus, gin.H{
		"status":    status,
		"timestamp": time.Now().UTC(),
		"checks":    checks,
	})
}

// ReadinessCheck godoc
// @Summary      Readiness Check
// @Description  Checks if the service is ready to accept traffic.
// @Tags         health
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      503  {object}  map[string]interface{}
// @Router       /ready [get]
func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	h.HealthCheck(c) // For now, readiness is the same as healthiness
}

func (h *HealthHandler) performChecks() map[string]string {
	var wg sync.WaitGroup
	checks := make(map[string]string)
	mu := &sync.Mutex{}

	checkers := map[string]func(){
		"database": func() { h.checkDatabase(mu, checks) },
		"redis":    func() { h.checkRedis(mu, checks) },
		"vault":    func() { h.checkVault(mu, checks) },
	}

	wg.Add(len(checkers))
	for _, checkFunc := range checkers {
		go func(f func()) {
			defer wg.Done()
			f()
		}(checkFunc)
	}
	wg.Wait()
	return checks
}

func (h *HealthHandler) checkDatabase(mu *sync.Mutex, checks map[string]string) {
	status := "ok"
	if err := h.db.Ping(context.Background()); err != nil {
		status = "error: " + err.Error()
	}
	mu.Lock()
	checks["database"] = status
	mu.Unlock()
}

func (h *HealthHandler) checkRedis(mu *sync.Mutex, checks map[string]string) {
	status := "ok"
	if err := h.redis.Ping(context.Background()); err != nil {
		status = "error: " + err.Error()
	}
	mu.Lock()
	checks["redis"] = status
	mu.Unlock()
}

func (h *HealthHandler) checkVault(mu *sync.Mutex, checks map[string]string) {
	// A real implementation would check vault's health endpoint
	status := "ok"
	mu.Lock()
	checks["vault"] = status
	mu.Unlock()
}

//Personal.AI order the ending
