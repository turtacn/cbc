//go:build integration
package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/pkg/logger"
)

func TestHealthCheckIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	log := logger.NewNoopLogger()

	// Postgres container
	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:13-alpine"),
		postgres.WithDatabase("test-db"),
		postgres.WithUsername("user"),
		postgres.WithPassword("password"),
		wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(5*time.Second),
	)
	require.NoError(t, err)
	defer pgContainer.Terminate(ctx)

	pgConnStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	dbConn, err := postgres.NewDBConnection(ctx, &config.DatabaseConfig{DSN: pgConnStr}, log)
	require.NoError(t, err)

	// Redis container
	redisContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		Image:   "redis:6-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor: wait.ForLog("* Ready to accept connections"),
	})
	require.NoError(t, err)
	defer redisContainer.Terminate(ctx)

	redisHost, err := redisContainer.Host(ctx)
	require.NoError(t, err)
	redisPort, err := redisContainer.MappedPort(ctx, "6379")
	require.NoError(t, err)

	redisConn := redis.NewRedisConnection(&redis.Config{
		Mode:     redis.ModeStandalone,
		Host:     redisHost,
		Port:     redisPort.Int(),
	}, log)
	err = redisConn.Connect()
	require.NoError(t, err)


	healthHandler := handlers.NewHealthHandler(dbConn, redisConn, log)

	router := gin.New()
	router.GET("/health/ready", healthHandler.ReadinessCheck)
	router.GET("/health/live", healthHandler.LivenessCheck)

	t.Run("should return 200 when all dependencies are healthy", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/health/ready", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should always return 200 for liveness check", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/health/live", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
