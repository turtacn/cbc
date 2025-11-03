//go:build unit

package infrastructure_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/infrastructure/kms"
	"github.com/turtacn/cbc/pkg/logger"
)

// MockVault is a mock of the Vault Logical client
type MockVaultLogical struct {
	mock.Mock
}

func (m *MockVaultLogical) Read(path string) (*api.Secret, error) {
	args := m.Called(path)
	return args.Get(0).(*api.Secret), args.Error(1)
}

type VaultAdapterTestSuite struct {
	suite.Suite
	adapter      kms.KeyManagementService
	mockVault    *MockVaultLogical
	redisServer  *miniredis.Miniredis
	redisClient  *redis.Client
	privateKey   *rsa.PrivateKey
	publicKeyPEM string
}

func (suite *VaultAdapterTestSuite) SetupSuite() {
	var err error
	suite.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(suite.T(), err)

	pubASN1, err := x509.MarshalPKIXPublicKey(&suite.privateKey.PublicKey)
	assert.NoError(suite.T(), err)
	suite.publicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}))

	suite.redisServer, err = miniredis.Run()
	assert.NoError(suite.T(), err)

	suite.redisClient = redis.NewClient(&redis.Options{
		Addr: suite.redisServer.Addr(),
	})
}

func (suite *VaultAdapterTestSuite) TearDownSuite() {
	suite.redisServer.Close()
}

func (suite *VaultAdapterTestSuite) SetupTest() {
	suite.mockVault = new(MockVaultLogical)

	// Create a mock Vault client
	mockVaultClient := &api.Client{}
	mockVaultClient.SetLogical(suite.mockVault)

	cfg := config.VaultConfig{
		KeyCacheTTL: 1 * time.Hour,
	}

	var err error
	suite.adapter, err = kms.NewVaultAdapter(cfg, mockVaultClient, suite.redisClient, logger.NewNoopLogger())
	assert.NoError(suite.T(), err)
}

func (suite *VaultAdapterTestSuite) TestGetTenantPublicKey_CacheMiss() {
	tenantID := "test-tenant"
	keyID := "test-key"

	secret := &api.Secret{
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"public_key": suite.publicKeyPEM,
			},
		},
	}
	suite.mockVault.On("Read", mock.Anything).Return(secret, nil)

	pubKey, err := suite.adapter.GetPublicKey(context.Background(), tenantID, keyID)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), pubKey)
	assert.Equal(suite.T(), &suite.privateKey.PublicKey, pubKey)

	suite.mockVault.AssertExpectations(suite.T())
}

func TestVaultAdapterTestSuite(t *testing.T) {
	suite.Run(t, new(VaultAdapterTestSuite))
}
