// Package kms implements the KeyManagementService interface using HashiCorp Vault.
package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"
	vault "github.com/hashicorp/vault/api"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// VaultProvider is a Vault-backed implementation of the KeyProvider interface.
type VaultProvider struct {
	vaultClient *vault.Client
	logger      logger.Logger
	config      config.VaultConfig
}

// NewVaultProvider creates a new VaultProvider.
func NewVaultProvider(cfg config.VaultConfig, vaultClient *vault.Client, logger logger.Logger) (service.KeyProvider, error) {
	return &VaultProvider{
		vaultClient: vaultClient,
		logger:      logger.WithComponent("VaultProvider"),
		config:      cfg,
	}, nil
}

// GenerateKey creates a new key in Vault.
func (p *VaultProvider) GenerateKey(ctx context.Context, keySpec models.KeySpec) (string, string, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySpec.Bits)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	kid := "kid-" + uuid.New().String()
	providerRef := fmt.Sprintf("secret/data/cbc/keys/%s", kid)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"private_key": string(privateKeyPEM),
			"public_key":  string(publicKeyPEM),
		},
	}

	_, err = p.vaultClient.Logical().Write(providerRef, secretData)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to write key to vault: %w", err)
	}

	return kid, providerRef, &privateKey.PublicKey, nil
}

// Sign uses a key from Vault to sign a digest.
func (p *VaultProvider) Sign(ctx context.Context, providerRef string, digest []byte) ([]byte, error) {
	privateKey, err := p.getPrivateKeyFromVault(ctx, providerRef)
	if err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, privateKey, 0, digest)
}

// GetPublicKey retrieves a public key from Vault.
func (p *VaultProvider) GetPublicKey(ctx context.Context, providerRef string) (*rsa.PublicKey, error) {
	secret, err := p.vaultClient.Logical().Read(providerRef)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve public key from vault: %w", err)
	}
	if secret == nil || secret.Data["data"] == nil {
		return nil, fmt.Errorf("key not found in vault for ref %s", providerRef)
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret format in vault")
	}

	pemData, ok := data["public_key"].(string)
	if !ok {
		return nil, fmt.Errorf("public_key not found or not a string in vault secret")
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return rsaPub, nil
}

// Backup retrieves a private key from Vault for backup.
func (p *VaultProvider) Backup(ctx context.Context, providerRef string) ([]byte, error) {
	privateKey, err := p.getPrivateKeyFromVault(ctx, providerRef)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// In a real implementation, this would be encrypted with a Master Backup Key (MBK).
	// For now, we return the raw PEM.
	return privateKeyPEM, nil
}

// Restore restores a key to Vault.
func (p *VaultProvider) Restore(ctx context.Context, encryptedBlob []byte) (string, error) {
	// In a real implementation, this would be decrypted with a Master Backup Key (MBK).
	block, _ := pem.Decode(encryptedBlob)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	kid := "kid-" + uuid.New().String()
	providerRef := fmt.Sprintf("secret/data/cbc/keys/%s", kid)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"private_key": string(encryptedBlob),
			"public_key":  string(publicKeyPEM),
		},
	}

	_, err = p.vaultClient.Logical().Write(providerRef, secretData)
	if err != nil {
		return "", fmt.Errorf("failed to write key to vault: %w", err)
	}

	return providerRef, nil
}

func (p *VaultProvider) getPrivateKeyFromVault(ctx context.Context, providerRef string) (*rsa.PrivateKey, error) {
	secret, err := p.vaultClient.Logical().Read(providerRef)
	if err != nil {
		p.logger.Error(ctx, "failed to read private key from Vault", err, logger.String("provider_ref", providerRef))
		return nil, fmt.Errorf("could not retrieve private key from vault: %w", err)
	}
	if secret == nil || secret.Data["data"] == nil {
		return nil, fmt.Errorf("key not found in vault for ref %s", providerRef)
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret format in vault")
	}

	pemData, ok := data["private_key"].(string)
	if !ok {
		return nil, fmt.Errorf("private_key not found or not a string in vault secret")
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		p.logger.Error(ctx, "failed to parse RSA private key from PEM", err, logger.String("provider_ref", providerRef))
		return nil, fmt.Errorf("could not parse private key: %w", err)
	}

	return privateKey, nil
}
