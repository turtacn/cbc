//go:build integration

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/turtacn/cbc/internal/application"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/internal/infrastructure/cdn"
	pgInfra "github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	"github.com/turtacn/cbc/pkg/logger"
)

// MockKeyProvider is a mock implementation of the KeyProvider interface for E2E tests.
type MockKeyProvider struct {
	mock.Mock
}

func (m *MockKeyProvider) GenerateKey(ctx context.Context, keySpec models.KeySpec) (string, string, *rsa.PublicKey, error) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "mock-kid-" + uuid.New().String()
	return kid, "mock-ref", &privateKey.PublicKey, nil
}

func (m *MockKeyProvider) Sign(ctx context.Context, providerRef string, digest []byte) ([]byte, error) {
	return nil, nil
}

func (m *MockKeyProvider) GetPublicKey(ctx context.Context, providerRef string) (*rsa.PublicKey, error) {
	return nil, nil
}

func (m *MockKeyProvider) Backup(ctx context.Context, providerRef string) ([]byte, error) {
	return nil, nil
}

func (m *MockKeyProvider) Restore(ctx context.Context, encryptedBlob []byte) (string, error) {
	return "", nil
}

type E2ETestSuite struct {
	App         *TestApp
	KMS         service.KeyManagementService
	TenantRepo  repository.TenantRepository
	pgContainer *postgres.PostgresContainer
	dbConn      *pgInfra.DBConnection
}

type TestApp struct {
	kms        *application.KeyManagementService
	cdnManager service.CDNCacheManager
}

func (a *TestApp) SetCDNCacheManager(cdnManager service.CDNCacheManager) {
	a.kms.SetCDNCacheManager(cdnManager)
}

func NewE2ETestSuite() (*E2ETestSuite, error) {
	ctx := context.Background()
	log := logger.NewNoopLogger()

	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("test-db"),
		postgres.WithUsername("user"),
		postgres.WithPassword("password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Minute),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start postgres container: %w", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, fmt.Errorf("failed to get connection string: %w", err)
	}

	dbCfg := &config.DatabaseConfig{
		DSN: connStr,
	}

	dbConn, err := pgInfra.NewDBConnection(ctx, dbCfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to test postgres: %w", err)
	}

	// Apply migrations
	migrationsDir := "../../migrations"
	files, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() < files[j].Name()
	})
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(migrationsDir, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", file.Name(), err)
		}
		if err := dbConn.DB().Exec(string(content)).Error; err != nil {
			return nil, fmt.Errorf("failed to apply migration %s: %w", file.Name(), err)
		}
	}

	tenantRepo := pgInfra.NewTenantRepository(dbConn.DB(), log)
	keyRepo := pgInfra.NewKeyRepository(dbConn.DB())

	cdnManager := cdn.NewStubAdapter(log)

	keyProviders := map[string]service.KeyProvider{
		"vault": &MockKeyProvider{},
	}

	kms, err := application.NewKeyManagementService(keyProviders, keyRepo, cdnManager, log)
	if err != nil {
		return nil, err
	}

	app := &TestApp{
		kms:        kms,
		cdnManager: cdnManager,
	}

	return &E2ETestSuite{
		App:         app,
		KMS:         kms,
		TenantRepo:  tenantRepo,
		pgContainer: pgContainer,
		dbConn:      dbConn,
	}, nil
}

func (s *E2ETestSuite) TearDown() {
	ctx := context.Background()
	if s.dbConn != nil {
		s.dbConn.Close()
	}
	if s.pgContainer != nil {
		_ = s.pgContainer.Terminate(ctx)
	}
}

func TestMain(m *testing.M) {
	if _, err := os.Stat("/var/run/podman/podman.sock"); err == nil {
		os.Setenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", "/var/run/podman/podman.sock")
	} else if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		os.Setenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", "/var/run/docker.sock")
	}
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	code := m.Run()
	os.Exit(code)
}
