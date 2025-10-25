package crypto

import (
	"context"
	"path"

	vault "github.com/hashicorp/vault/api"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// VaultClient provides an interface for interacting with HashiCorp Vault.
type VaultClient interface {
	GetKey(ctx context.Context, keyPath string) (map[string]interface{}, *errors.AppError)
	SaveKey(ctx context.Context, keyPath string, data map[string]interface{}) *errors.AppError
	DeleteKey(ctx context.Context, keyPath string) *errors.AppError
	ListKeys(ctx context.Context, dirPath string) ([]string, *errors.AppError)
}

type vaultClientImpl struct {
	client    *vault.Client
	log       logger.Logger
	mountPath string
}

// NewVaultClient creates and configures a new Vault client.
func NewVaultClient(cfg *config.VaultConfig, log logger.Logger) (VaultClient, error) {
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = cfg.Address

	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}
	client.SetToken(cfg.Token)

	// A real implementation would use AppRole or another auth method.
	// For now, we assume a root/dev token is provided.

	return &vaultClientImpl{
		client:    client,
		log:       log,
		mountPath: cfg.MountPath,
	}, nil
}

func (v *vaultClientImpl) GetKey(ctx context.Context, keyPath string) (map[string]interface{}, *errors.AppError) {
	fullPath := v.getSecretPath(keyPath)
	secret, err := v.client.KVv2("secret").Get(ctx, fullPath)
	if err != nil {
		return nil, errors.ErrVault.WithError(err)
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.ErrNotFound
	}
	return secret.Data, nil
}

func (v *vaultClientImpl) SaveKey(ctx context.Context, keyPath string, data map[string]interface{}) *errors.AppError {
	fullPath := v.getSecretPath(keyPath)
	_, err := v.client.KVv2("secret").Put(ctx, fullPath, data)
	if err != nil {
		return errors.ErrVault.WithError(err)
	}
	return nil
}

func (v *vaultClientImpl) DeleteKey(ctx context.Context, keyPath string) *errors.AppError {
	fullPath := v.getSecretPath(keyPath)
	if err := v.client.KVv2("secret").Delete(ctx, fullPath); err != nil {
		return errors.ErrVault.WithError(err)
	}
	return nil
}

func (v *vaultClientImpl) ListKeys(ctx context.Context, dirPath string) ([]string, *errors.AppError) {
	fullPath := path.Join(v.mountPath, "metadata", dirPath)
	secret, err := v.client.Logical().List(fullPath)
	if err != nil {
		return nil, errors.ErrVault.WithError(err)
	}
	if secret == nil {
		return []string{}, nil
	}

	keys := make([]string, len(secret.Data["keys"].([]interface{})))
	for i, k := range secret.Data["keys"].([]interface{}) {
		keys[i] = k.(string)
	}
	return keys, nil
}

// getSecretPath constructs the full path for a secret in Vault's KVv2 engine.
func (v *vaultClientImpl) getSecretPath(keyPath string) string {
	return path.Join(v.mountPath, "data", keyPath)
}

//Personal.AI order the ending
