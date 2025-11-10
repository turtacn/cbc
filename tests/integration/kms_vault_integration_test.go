//go:build integration

package integration

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/internal/infrastructure/kms"
	"github.com/turtacn/cbc/pkg/logger"
)

type KmsVaultIntegrationTestSuite struct {
	suite.Suite
	provider    service.KeyProvider
	vaultClient *api.Client
	container   testcontainers.Container
}

func (s *KmsVaultIntegrationTestSuite) SetupSuite() {
	if os.Getenv("SKIP_DOCKER_TESTS") != "" {
		s.T().Skip("Skipping Docker-dependent tests")
	}
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "vault:1.15",
		ExposedPorts: []string{"8200/tcp"},
		Env: map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID": "myroot",
			"VAULT_ADDR":              "http://0.0.0.0:8200",
		},
		WaitingFor: wait.ForLog("Vault server started!").WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(s.T(), err)
	s.container = container

	host, err := container.Host(ctx)
	require.NoError(s.T(), err)
	port, err := container.MappedPort(ctx, "8200")
	require.NoError(s.T(), err)
	vaultAddr := "http://" + host + ":" + port.Port()

	cfg := &config.VaultConfig{
		Address: vaultAddr,
		Token:   "myroot",
	}

	vClient, err := api.NewClient(&api.Config{Address: vaultAddr})
	require.NoError(s.T(), err)
	vClient.SetToken("myroot")
	s.vaultClient = vClient

	// Enable the transit secrets engine
	err = s.vaultClient.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	})
	// Ignore if already enabled, which can happen in some test environments
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(s.T(), err)
	}

	provider, err := kms.NewVaultProvider(*cfg, s.vaultClient, logger.NewNoopLogger())
	require.NoError(s.T(), err)
	s.provider = provider
}

func (s *KmsVaultIntegrationTestSuite) TearDownSuite() {
	if s.container != nil {
		s.container.Terminate(context.Background())
	}
}

func (s *KmsVaultIntegrationTestSuite) TestKeyLifecycle() {
	ctx := context.Background()
	keySpec := models.KeySpec{
		Algorithm: "rsa-2048",
		Bits:      2048,
	}

	// 1. Generate a new key
	kid, providerRef, publicKey, err := s.provider.GenerateKey(ctx, keySpec)
	s.Require().NoError(err)
	s.NotEmpty(kid)
	s.NotEmpty(providerRef)
	s.NotNil(publicKey)
	s.Equal(2048, publicKey.N.BitLen())

	// 2. Get the public key
	retrievedPubKey, err := s.provider.GetPublicKey(ctx, providerRef)
	s.Require().NoError(err)
	s.NotNil(retrievedPubKey)
	s.True(publicKey.Equal(retrievedPubKey), "Retrieved public key should match the generated one")

	// 3. Sign a digest and verify the signature
	digest := sha256.Sum256([]byte("some data to be signed"))
	signature, err := s.provider.Sign(ctx, providerRef, digest[:])
	s.Require().NoError(err)
	s.NotEmpty(signature)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature)
	s.NoError(err, "Signature verification should succeed")
}

func TestKmsVaultIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(KmsVaultIntegrationTestSuite))
}
