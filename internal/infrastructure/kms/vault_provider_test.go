// Package kms_test provides tests for the kms package.
package kms_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/infrastructure/kms"
	"github.com/turtacn/cbc/pkg/logger"
)

func TestVaultProvider_GenerateKey(t *testing.T) {
	logger := logger.NewNoopLogger()
	cfg := config.VaultConfig{}

	// Create a mock Vault server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create a Vault client
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = ts.URL
	vaultClient, err := api.NewClient(vaultConfig)
	assert.NoError(t, err)

	provider, err := kms.NewVaultProvider(cfg, vaultClient, logger)
	assert.NoError(t, err)

	ctx := context.Background()
	keySpec := models.KeySpec{
		Algorithm: "RSA",
		Bits:      2048,
	}

	kid, providerRef, publicKey, err := provider.GenerateKey(ctx, keySpec)
	assert.NoError(t, err)
	assert.NotEmpty(t, kid)
	assert.NotEmpty(t, providerRef)
	assert.NotNil(t, publicKey)
}
