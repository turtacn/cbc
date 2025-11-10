//go:build integration

package e2e_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/application"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	infraPostgres "github.com/turtacn/cbc/internal/infrastructure/postgres"
	"github.com/turtacn/cbc/internal/infrastructure/policy"
	"github.com/turtacn/cbc/pkg/logger"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestSecurityComplianceFlow(t *testing.T) {
	// This test requires a running Postgres database.
	// Set the DATABASE_URL environment variable to the connection string.
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	// Create a temporary policy file
	policyFile, err := os.CreateTemp("", "policies.yaml")
	assert.NoError(t, err)
	defer os.Remove(policyFile.Name())

	_, err = policyFile.WriteString(`
L1:
  minKeySize: 2048
L3:
  minKeySize: 4096
`)
	assert.NoError(t, err)
	policyFile.Close()

	// Create a new logger
	log := logger.NewNoopLogger()

	// Create a new database connection
	db, err := gorm.Open(gormpostgres.Open(databaseURL), &gorm.Config{})
	assert.NoError(t, err)

	// Create the repositories
	keyRepo := postgres.NewKeyRepository(db)
	tenantRepo := postgres.NewTenantRepository(db, log)
	klr := infraPostgres.NewKLRRepository(db)
	riskRepo := infraPostgres.NewPostgresRiskRepository(db)

	// Create the policy engine
	policyEngine, err := policy.NewStaticPolicyEngine(policyFile.Name())
	assert.NoError(t, err)

	// Create the risk oracle
	riskOracle := application.NewRiskOracle(riskRepo)

	// Create the key management service
	kms, err := application.NewKeyManagementService(
		nil, // keyProviders not needed for this test
		keyRepo,
		tenantRepo,
		policyEngine,
		klr,
		log,
		riskOracle,
	)
	assert.NoError(t, err)

	// Create a new tenant
	tenant := &models.Tenant{
		TenantID:        "test-tenant-l3",
		TenantName:      "Test Tenant L3",
		ComplianceClass: "L3",
	}
	err = tenantRepo.Save(context.Background(), tenant)
	assert.NoError(t, err)

	// Test case: Policy Block
	// This should fail because the key size is too small for L3
	_, err = kms.RotateTenantKey(context.Background(), tenant.TenantID, &service.StubCDNCacheManager{})
	assert.Error(t, err)
}
