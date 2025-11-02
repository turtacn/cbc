//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/turtacn/cbc/internal/domain/models"
	postgres_infra "github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	"github.com/turtacn/cbc/pkg/logger"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestDeviceRepository(t *testing.T) {
	if os.Getenv("SKIP_DOCKER_TESTS") == "true" {
		t.Skip("Skipping Docker-dependent tests")
	}

	ctx := context.Background()
	dbName := "testdb"
	dbUser := "user"
	dbPassword := "password"

	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Minute),
		),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, pgContainer.Terminate(ctx))
	}()

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{})
	require.NoError(t, err)

	// Run migrations
	migrationsPath, err := filepath.Abs("../../migrations/0001_devices.sql")
	require.NoError(t, err)
	sqlBytes, err := os.ReadFile(migrationsPath)
	require.NoError(t, err)
	err = db.Exec(string(sqlBytes)).Error
	require.NoError(t, err)

	log := logger.NewDefaultLogger()
	repo := postgres_infra.NewDeviceRepository(db, log)

	tenantID := uuid.New().String()
	deviceID := uuid.New().String()

	// Test Save
	device := &models.Device{
		TenantID:    tenantID,
		DeviceID:    deviceID,
		DisplayName: "Test Device",
		Platform:    "linux",
		AgentVersion: "1.0.0",
	}
	err = repo.Save(ctx, device)
	assert.NoError(t, err)

	// Test FindByID
	retrievedDevice, err := repo.FindByID(ctx, deviceID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedDevice)
	assert.Equal(t, "Test Device", retrievedDevice.DisplayName)

	// Test Update
	retrievedDevice.DisplayName = "Updated Device"
	err = repo.Update(ctx, retrievedDevice)
	assert.NoError(t, err)

	// Verify Update
	updatedDevice, err := repo.FindByID(ctx, deviceID)
	assert.NoError(t, err)
	assert.NotNil(t, updatedDevice)
	assert.Equal(t, "Updated Device", updatedDevice.DisplayName)

	// Test FindByID not found
	_, err = repo.FindByID(ctx, "non-existent-device")
	assert.Error(t, err)

	// Test FindByTenantID
	devices, total, err := repo.FindByTenantID(ctx, tenantID, 1, 10)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, devices, 1)
}
