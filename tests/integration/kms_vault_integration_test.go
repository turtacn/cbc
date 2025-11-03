//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/internal/infrastructure/kms"
	"github.com/turtacn/cbc/pkg/logger"
)

type KmsVaultIntegrationTestSuite struct {
	suite.Suite
	adapter    service.CryptoService
	vaultClient *api.Client
	privateKey *rsa.PrivateKey
}

func (suite *KmsVaultIntegrationTestSuite) SetupSuite() {
	var err error
	suite.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(suite.T(), err)

	cfg := api.DefaultConfig()
	cfg.Address = "http://localhost:8200"
	suite.vaultClient, err = api.NewClient(cfg)
	assert.NoError(suite.T(), err)
	suite.vaultClient.SetToken("myroot")

	// Write a secret to Vault for testing
	privBytes := x509.MarshalPKCS1PrivateKey(suite.privateKey)
	pubBytes, err := x509.MarshalPKIXPublicKey(&suite.privateKey.PublicKey)
	assert.NoError(suite.T(), err)

	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})),
			"public_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})),
		},
	}
	_, err = suite.vaultClient.Logical().Write("secret/data/cbc/tenants/test-tenant/keys/key-001", secretData)
	assert.NoError(suite.T(), err)
}

func (suite *KmsVaultIntegrationTestSuite) SetupTest() {
	cfg := config.VaultConfig{}
	var err error
	suite.adapter, err = kms.NewVaultAdapter(cfg, suite.vaultClient, nil, logger.NewNoopLogger())
	assert.NoError(suite.T(), err)
}

func (suite *KmsVaultIntegrationTestSuite) TestGetTenantPublicKey() {
	pubKey, err := suite.adapter.GetPublicKey(context.Background(), "test-tenant", "key-001")
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), pubKey)
	assert.Equal(suite.T(), &suite.privateKey.PublicKey, pubKey)
}

func (suite *KmsVaultIntegrationTestSuite) TestGetTenantPrivateKey() {
	privKey, kid, err := suite.adapter.GetPrivateKey(context.Background(), "test-tenant")
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), privKey)
	assert.Equal(suite.T(), "key-001", kid)
	assert.Equal(suite.T(), suite.privateKey, privKey)
}

func TestKmsVaultIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(KmsVaultIntegrationTestSuite))
}
