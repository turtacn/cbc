// Package crypto provides cryptographic services and secret management using HashiCorp Vault.
// It includes secret storage, encryption/decryption, dynamic credentials, and key management.
package crypto

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"

	"github.com/turtacn/cbc/pkg/logger"
)

// VaultClient provides a high-level interface for interacting with HashiCorp Vault.
type VaultClient struct {
	client        *vault.Client
	logger        logger.Logger
	config        *VaultConfig
	tokenRenewer  *vault.Renewer
	renewerMutex  sync.Mutex
	renewerCancel context.CancelFunc
}

// VaultConfig holds Vault client configuration.
type VaultConfig struct {
	// Address is the Vault server address
	Address string
	// Token is the authentication token
	Token string
	// Namespace for multi-tenancy (Vault Enterprise)
	Namespace string
	// MaxRetries for API requests
	MaxRetries int
	// Timeout for API requests
	Timeout time.Duration
	// TokenRenewal enables automatic token renewal
	TokenRenewal bool
	// RenewalInterval for token renewal
	RenewalInterval time.Duration
	// TLSConfig for secure connections
	TLSConfig *TLSConfig
}

// TLSConfig holds TLS configuration for Vault connections.
type TLSConfig struct {
	// CACert path to CA certificate
	CACert string
	// ClientCert path to client certificate
	ClientCert string
	// ClientKey path to client key
	ClientKey string
	// Insecure skips TLS verification (not recommended for production)
	Insecure bool
}

// SecretData represents secret key-value pairs.
type SecretData map[string]interface{}

// EncryptionRequest represents a request to encrypt data.
type EncryptionRequest struct {
	// Plaintext data to encrypt (will be base64 encoded)
	Plaintext []byte
	// Context for key derivation (optional)
	Context []byte
	// KeyVersion to use for encryption (optional, uses latest by default)
	KeyVersion int
}

// EncryptionResponse represents the result of an encryption operation.
type EncryptionResponse struct {
	// Ciphertext is the encrypted data
	Ciphertext string
	// KeyVersion used for encryption
	KeyVersion int
}

// DecryptionRequest represents a request to decrypt data.
type DecryptionRequest struct {
	// Ciphertext to decrypt
	Ciphertext string
	// Context for key derivation (must match encryption context)
	Context []byte
}

// DecryptionResponse represents the result of a decryption operation.
type DecryptionResponse struct {
	// Plaintext is the decrypted data
	Plaintext []byte
	// KeyVersion used for decryption
	KeyVersion int
}

// DynamicCredentials represents dynamically generated credentials.
type DynamicCredentials struct {
	// Username for the credential
	Username string
	// Password for the credential
	Password string
	// LeaseDuration is how long the credential is valid
	LeaseDuration time.Duration
	// LeaseID for renewal/revocation
	LeaseID string
	// Renewable indicates if the lease can be renewed
	Renewable bool
}

// NewVaultClient creates a new Vault client instance.
//
// Parameters:
//   - config: Vault configuration
//   - log: Logger instance
//
// Returns:
//   - *VaultClient: Initialized Vault client
//   - error: Initialization error if any
func NewVaultClient(config *VaultConfig, log logger.Logger) (*VaultClient, error) {
	if config == nil {
		return nil, fmt.Errorf("vault config is required")
	}

	// Create Vault client configuration
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Address

	if config.Timeout > 0 {
		vaultConfig.Timeout = config.Timeout
	}

	if config.MaxRetries > 0 {
		vaultConfig.MaxRetries = config.MaxRetries
	}

	// Configure TLS if provided
	if config.TLSConfig != nil {
		tlsConfig := &vault.TLSConfig{
			CACert:     config.TLSConfig.CACert,
			ClientCert: config.TLSConfig.ClientCert,
			ClientKey:  config.TLSConfig.ClientKey,
			Insecure:   config.TLSConfig.Insecure,
		}
		if err := vaultConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	// Create Vault API client
	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Set authentication token
	client.SetToken(config.Token)

	// Set namespace if provided (Vault Enterprise feature)
	if config.Namespace != "" {
		client.SetNamespace(config.Namespace)
	}

	vc := &VaultClient{
		client: client,
		logger: log,
		config: config,
	}

	// Start automatic token renewal if enabled
	if config.TokenRenewal {
		if err := vc.startTokenRenewal(context.Background()); err != nil {
			log.Warn("Failed to start token renewal", "error", err)
		}
	}

	log.Info("Vault client initialized",
		"address", config.Address,
		"namespace", config.Namespace,
	)

	return vc, nil
}

// startTokenRenewal starts automatic token renewal.
func (vc *VaultClient) startTokenRenewal(ctx context.Context) error {
	vc.renewerMutex.Lock()
	defer vc.renewerMutex.Unlock()

	// Lookup current token to get renewable status
	secret, err := vc.client.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("failed to lookup token: %w", err)
	}

	renewable, _ := secret.TokenIsRenewable()
	if !renewable {
		vc.logger.Warn("Token is not renewable, skipping renewal setup")
		return nil
	}

	// Create renewer
	renewer, err := vc.client.NewRenewer(&vault.RenewerInput{
		Secret: secret,
	})
	if err != nil {
		return fmt.Errorf("failed to create renewer: %w", err)
	}

	// Start renewal goroutine
	renewCtx, cancel := context.WithCancel(ctx)
	vc.renewerCancel = cancel
	vc.tokenRenewer = renewer

	go vc.renewalLoop(renewCtx, renewer)

	vc.logger.Info("Token renewal started")
	return nil
}

// renewalLoop handles token renewal events.
func (vc *VaultClient) renewalLoop(ctx context.Context, renewer *vault.Renewer) {
	go renewer.Renew()
	defer renewer.Stop()

	for {
		select {
		case err := <-renewer.DoneCh():
			if err != nil {
				vc.logger.Error("Token renewal failed", "error", err)
			}
			vc.logger.Info("Token renewal stopped")
			return

		case renewal := <-renewer.RenewCh():
			vc.logger.Debug("Token renewed",
				"lease_duration", renewal.Secret.LeaseDuration,
			)

		case <-ctx.Done():
			vc.logger.Info("Token renewal cancelled")
			return
		}
	}
}

// StopTokenRenewal stops automatic token renewal.
func (vc *VaultClient) StopTokenRenewal() {
	vc.renewerMutex.Lock()
	defer vc.renewerMutex.Unlock()

	if vc.renewerCancel != nil {
		vc.renewerCancel()
		vc.renewerCancel = nil
	}

	if vc.tokenRenewer != nil {
		vc.tokenRenewer.Stop()
		vc.tokenRenewer = nil
	}

	vc.logger.Info("Token renewal stopped")
}

// WriteSecret writes a secret to Vault KV store.
//
// Parameters:
//   - ctx: Context for timeout control
//   - path: Secret path (e.g., "secret/data/myapp/config")
//   - data: Secret data to store
//
// Returns:
//   - error: Write operation error if any
func (vc *VaultClient) WriteSecret(ctx context.Context, path string, data SecretData) error {
	// For KV v2, wrap data in "data" field
	wrappedData := map[string]interface{}{
		"data": data,
	}

	_, err := vc.client.Logical().WriteWithContext(ctx, path, wrappedData)
	if err != nil {
		vc.logger.Error("Failed to write secret",
			"path", path,
			"error", err,
		)
		return fmt.Errorf("failed to write secret: %w", err)
	}

	vc.logger.Debug("Secret written", "path", path)
	return nil
}

// ReadSecret reads a secret from Vault KV store.
//
// Parameters:
//   - ctx: Context for timeout control
//   - path: Secret path
//
// Returns:
//   - SecretData: Secret data
//   - error: Read operation error if any
func (vc *VaultClient) ReadSecret(ctx context.Context, path string) (SecretData, error) {
	secret, err := vc.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		vc.logger.Error("Failed to read secret",
			"path", path,
			"error", err,
		)
		return nil, fmt.Errorf("failed to read secret: %w", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", path)
	}

	// For KV v2, extract data from "data" field
	if dataRaw, ok := secret.Data["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			vc.logger.Debug("Secret read", "path", path)
			return data, nil
		}
	}

	// Fallback for KV v1 or direct data access
	vc.logger.Debug("Secret read", "path", path)
	return secret.Data, nil
}

// DeleteSecret deletes a secret from Vault KV store.
//
// Parameters:
//   - ctx: Context for timeout control
//   - path: Secret path
//
// Returns:
//   - error: Delete operation error if any
func (vc *VaultClient) DeleteSecret(ctx context.Context, path string) error {
	_, err := vc.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		vc.logger.Error("Failed to delete secret",
			"path", path,
			"error", err,
		)
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	vc.logger.Debug("Secret deleted", "path", path)
	return nil
}

// ListSecrets lists secrets at a given path.
//
// Parameters:
//   - ctx: Context for timeout control
//   - path: Path to list
//
// Returns:
//   - []string: List of secret keys
//   - error: List operation error if any
func (vc *VaultClient) ListSecrets(ctx context.Context, path string) ([]string, error) {
	secret, err := vc.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		vc.logger.Error("Failed to list secrets",
			"path", path,
			"error", err,
		)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	if keysRaw, ok := secret.Data["keys"]; ok {
		if keys, ok := keysRaw.([]interface{}); ok {
			result := make([]string, 0, len(keys))
			for _, key := range keys {
				if keyStr, ok := key.(string); ok {
					result = append(result, keyStr)
				}
			}
			return result, nil
		}
	}

	return []string{}, nil
}

// Encrypt encrypts data using Vault's transit engine.
//
// Parameters:
//   - ctx: Context for timeout control
//   - keyName: Name of the encryption key
//   - req: Encryption request
//
// Returns:
//   - *EncryptionResponse: Encryption response
//   - error: Encryption error if any
func (vc *VaultClient) Encrypt(ctx context.Context, keyName string, req *EncryptionRequest) (*EncryptionResponse, error) {
	path := fmt.Sprintf("transit/encrypt/%s", keyName)

	// Prepare request data
	data := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(req.Plaintext),
	}

	if len(req.Context) > 0 {
		data["context"] = base64.StdEncoding.EncodeToString(req.Context)
	}

	if req.KeyVersion > 0 {
		data["key_version"] = req.KeyVersion
	}

	// Perform encryption
	secret, err := vc.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		vc.logger.Error("Failed to encrypt data",
			"key", keyName,
			"error", err,
		)
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid ciphertext response")
	}

	response := &EncryptionResponse{
		Ciphertext: ciphertext,
	}

	if keyVersion, ok := secret.Data["key_version"].(int); ok {
		response.KeyVersion = keyVersion
	}

	vc.logger.Debug("Data encrypted",
		"key", keyName,
		"key_version", response.KeyVersion,
	)

	return response, nil
}

// Decrypt decrypts data using Vault's transit engine.
//
// Parameters:
//   - ctx: Context for timeout control
//   - keyName: Name of the encryption key
//   - req: Decryption request
//
// Returns:
//   - *DecryptionResponse: Decryption response
//   - error: Decryption error if any
func (vc *VaultClient) Decrypt(ctx context.Context, keyName string, req *DecryptionRequest) (*DecryptionResponse, error) {
	path := fmt.Sprintf("transit/decrypt/%s", keyName)

	// Prepare request data
	data := map[string]interface{}{
		"ciphertext": req.Ciphertext,
	}

	if len(req.Context) > 0 {
		data["context"] = base64.StdEncoding.EncodeToString(req.Context)
	}

	// Perform decryption
	secret, err := vc.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		vc.logger.Error("Failed to decrypt data",
			"key", keyName,
			"error", err,
		)
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	plaintextB64, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid plaintext response")
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plaintext: %w", err)
	}

	response := &DecryptionResponse{
		Plaintext: plaintext,
	}

	if keyVersion, ok := secret.Data["key_version"].(int); ok {
		response.KeyVersion = keyVersion
	}

	vc.logger.Debug("Data decrypted",
		"key", keyName,
		"key_version", response.KeyVersion,
	)

	return response, nil
}

// GenerateDataKey generates a new data encryption key.
//
// Parameters:
//   - ctx: Context for timeout control
//   - keyName: Name of the encryption key
//   - bits: Key size in bits (128, 256, or 512)
//
// Returns:
//   - []byte: Plaintext key
//   - string: Encrypted key (ciphertext)
//   - error: Generation error if any
func (vc *VaultClient) GenerateDataKey(ctx context.Context, keyName string, bits int) ([]byte, string, error) {
	path := fmt.Sprintf("transit/datakey/plaintext/%s", keyName)

	data := map[string]interface{}{
		"bits": bits,
	}

	secret, err := vc.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		vc.logger.Error("Failed to generate data key",
			"key", keyName,
			"bits", bits,
			"error", err,
		)
		return nil, "", fmt.Errorf("failed to generate data key: %w", err)
	}

	plaintextB64, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, "", fmt.Errorf("invalid plaintext in response")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return nil, "", fmt.Errorf("invalid ciphertext in response")
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode plaintext: %w", err)
	}

	vc.logger.Debug("Data key generated",
		"key", keyName,
		"bits", bits,
	)

	return plaintext, ciphertext, nil
}

// GetDynamicDBCredentials generates dynamic database credentials.
//
// Parameters:
//   - ctx: Context for timeout control
//   - role: Database role name
//
// Returns:
//   - *DynamicCredentials: Generated credentials
//   - error: Generation error if any
func (vc *VaultClient) GetDynamicDBCredentials(ctx context.Context, role string) (*DynamicCredentials, error) {
	path := fmt.Sprintf("database/creds/%s", role)

	secret, err := vc.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		vc.logger.Error("Failed to get dynamic DB credentials",
			"role", role,
			"error", err,
		)
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("no credentials returned for role: %s", role)
	}

	username, _ := secret.Data["username"].(string)
	password, _ := secret.Data["password"].(string)

	creds := &DynamicCredentials{
		Username:      username,
		Password:      password,
		LeaseDuration: time.Duration(secret.LeaseDuration) * time.Second,
		LeaseID:       secret.LeaseID,
		Renewable:     secret.Renewable,
	}

	vc.logger.Debug("Dynamic DB credentials generated",
		"role", role,
		"username", username,
		"lease_duration", creds.LeaseDuration,
	)

	return creds, nil
}

// RenewLease renews a lease.
//
// Parameters:
//   - ctx: Context for timeout control
//   - leaseID: Lease ID to renew
//   - increment: Increment duration (0 for default)
//
// Returns:
//   - time.Duration: New lease duration
//   - error: Renewal error if any
func (vc *VaultClient) RenewLease(ctx context.Context, leaseID string, increment time.Duration) (time.Duration, error) {
	incrementSeconds := int(increment.Seconds())

	secret, err := vc.client.Sys().RenewWithContext(ctx, leaseID, incrementSeconds)
	if err != nil {
		vc.logger.Error("Failed to renew lease",
			"lease_id", leaseID,
			"error", err,
		)
		return 0, fmt.Errorf("failed to renew lease: %w", err)
	}

	duration := time.Duration(secret.LeaseDuration) * time.Second

	vc.logger.Debug("Lease renewed",
		"lease_id", leaseID,
		"duration", duration,
	)

	return duration, nil
}

// RevokeLease revokes a lease.
//
// Parameters:
//   - ctx: Context for timeout control
//   - leaseID: Lease ID to revoke
//
// Returns:
//   - error: Revocation error if any
func (vc *VaultClient) RevokeLease(ctx context.Context, leaseID string) error {
	err := vc.client.Sys().RevokeWithContext(ctx, leaseID)
	if err != nil {
		vc.logger.Error("Failed to revoke lease",
			"lease_id", leaseID,
			"error", err,
		)
		return fmt.Errorf("failed to revoke lease: %w", err)
	}

	vc.logger.Debug("Lease revoked", "lease_id", leaseID)
	return nil
}

// Health checks Vault server health.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - bool: True if healthy
//   - error: Health check error if any
func (vc *VaultClient) Health(ctx context.Context) (bool, error) {
	health, err := vc.client.Sys().HealthWithContext(ctx)
	if err != nil {
		vc.logger.Error("Health check failed", "error", err)
		return false, err
	}

	isHealthy := health.Initialized && !health.Sealed

	vc.logger.Debug("Health check completed",
		"initialized", health.Initialized,
		"sealed", health.Sealed,
		"healthy", isHealthy,
	)

	return isHealthy, nil
}

// Close closes the Vault client and stops token renewal.
func (vc *VaultClient) Close() error {
	vc.StopTokenRenewal()
	vc.logger.Info("Vault client closed")
	return nil
}
