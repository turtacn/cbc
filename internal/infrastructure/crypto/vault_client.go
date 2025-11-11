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

// VaultClient provides a high-level, opinionated interface for interacting with HashiCorp Vault.
// It simplifies common operations like KV secret management, transit encryption, and token renewal.
// VaultClient 提供与 HashiCorp Vault 交互的高级、自定义接口。
// 它简化了常见的操作，如 KV 秘密管理、传输加密和令牌续订。
type VaultClient struct {
	client        *vault.Client
	logger        logger.Logger
	config        *VaultConfig
	tokenRenewer  *vault.Renewer
	renewerMutex  sync.Mutex
	renewerCancel context.CancelFunc
}

// VaultConfig holds all necessary configuration for the Vault client.
// VaultConfig 保存 Vault 客户端的所有必要配置。
type VaultConfig struct {
	// Address is the network address of the Vault server.
	// Address 是 Vault 服务器的网络地址。
	Address string
	// Token is the authentication token used to communicate with Vault.
	// Token 是用于与 Vault 通信的身份验证令牌。
	Token string
	// Namespace is the Vault Enterprise namespace to operate within.
	// Namespace 是要操作的 Vault Enterprise 命名空间。
	Namespace string
	// MaxRetries is the maximum number of retries for failed API requests.
	// MaxRetries 是 API 请求失败的最大重试次数。
	MaxRetries int
	// Timeout is the timeout for API requests to Vault.
	// Timeout 是对 Vault 的 API 请求的超时时间。
	Timeout time.Duration
	// TokenRenewal enables automatic renewal of the Vault token.
	// TokenRenewal 启用 Vault 令牌的自动续订。
	TokenRenewal bool
	// RenewalInterval specifies how often to check for token renewal.
	// RenewalInterval 指定检查令牌续订的频率。
	RenewalInterval time.Duration
	// TLSConfig contains settings for establishing a secure TLS connection to Vault.
	// TLSConfig 包含用于建立到 Vault 的安全 TLS 连接的设置。
	TLSConfig *TLSConfig
}

// TLSConfig holds TLS settings for the Vault client connection.
// TLSConfig 保存 Vault 客户端连接的 TLS 设置。
type TLSConfig struct {
	// CACert is the path to the CA certificate file for verifying the Vault server's certificate.
	// CACert 是用于验证 Vault 服务器证书的 CA 证书文件的路径。
	CACert string
	// ClientCert is the path to the client's TLS certificate file.
	// ClientCert 是客户端 TLS 证书文件的路径。
	ClientCert string
	// ClientKey is the path to the client's TLS private key file.
	// ClientKey 是客户端 TLS 私钥文件的路径。
	ClientKey string
	// Insecure disables TLS certificate verification. Should not be used in production.
	// Insecure 禁用 TLS 证书验证。不应在生产环境中使用。
	Insecure bool
}

// SecretData represents a map of key-value pairs for a secret.
// SecretData 表示一个秘密的键值对映射。
type SecretData map[string]interface{}

// EncryptionRequest represents a request to encrypt data using Vault's transit secrets engine.
// EncryptionRequest 表示使用 Vault 的 transit 秘密引擎加密数据的请求。
type EncryptionRequest struct {
	// Plaintext is the raw data to be encrypted.
	// Plaintext 是要加密的原始数据。
	Plaintext []byte
	// Context is optional, context-specific data for key derivation (AAD).
	// Context 是用于密钥派生的可选的、特定于上下文的数据 (AAD)。
	Context []byte
	// KeyVersion specifies a particular version of the key to use for encryption. 0 means the latest.
	// KeyVersion 指定用于加密的密钥的特定版本。0 表示最新版本。
	KeyVersion int
}

// EncryptionResponse contains the result of an encryption operation.
// EncryptionResponse 包含加密操作的结果。
type EncryptionResponse struct {
	// Ciphertext is the base64-encoded encrypted data.
	// Ciphertext 是 base64 编码的加密数据。
	Ciphertext string
	// KeyVersion is the version of the key that was used for encryption.
	// KeyVersion 是用于加密的密钥的版本。
	KeyVersion int
}

// DecryptionRequest represents a request to decrypt data.
// DecryptionRequest 表示解密数据的请求。
type DecryptionRequest struct {
	// Ciphertext is the encrypted data to be decrypted.
	// Ciphertext 是要解密的加密数据。
	Ciphertext string
	// Context must match the context used during encryption, if any.
	// Context 必须与加密期间使用的上下文匹配（如果有）。
	Context []byte
}

// DecryptionResponse contains the result of a decryption operation.
// DecryptionResponse 包含解密操作的结果。
type DecryptionResponse struct {
	// Plaintext is the decrypted raw data.
	// Plaintext 是解密的原始数据。
	Plaintext []byte
	// KeyVersion is the version of the key that was used for decryption.
	// KeyVersion 是用于解密的密钥的版本。
	KeyVersion int
}

// DynamicCredentials represents credentials that are generated on-demand and have a limited lifetime.
// DynamicCredentials 表示按需生成且生命周期有限的凭据。
type DynamicCredentials struct {
	// Username is the generated username.
	// Username 是生成的用户名。
	Username string
	// Password is the generated password.
	// Password 是生成的密码。
	Password string
	// LeaseDuration is the duration for which the credentials are valid.
	// LeaseDuration 是凭据有效的持续时间。
	LeaseDuration time.Duration
	// LeaseID is the ID used to renew or revoke the credentials.
	// LeaseID 是用于续订或撤销凭据的 ID。
	LeaseID string
	// Renewable indicates whether the lease for these credentials can be renewed.
	// Renewable 指示这些凭据的租约是否可以续订。
	Renewable bool
}

// NewVaultClient creates and configures a new VaultClient instance.
// It initializes the underlying Vault API client, configures TLS, and optionally starts a background process for token renewal.
// NewVaultClient 创建并配置一个新的 VaultClient 实例。
// 它会初始化底层的 Vault API 客户端，配置 TLS，并可选择性地启动一个后台进程来续订令牌。
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
			log.Warn(context.Background(), "Failed to start token renewal", logger.Error(err))
		}
	}

	log.Info(context.Background(), "Vault client initialized",
		logger.String("address", config.Address),
		logger.String("namespace", config.Namespace),
	)

	return vc, nil
}

// startTokenRenewal is an internal helper that starts the background token renewal process.
// It checks if the token is renewable and sets up a goroutine to manage the renewal lifecycle.
// startTokenRenewal 是一个内部辅助函数，用于启动后台令牌续订过程。
// 它会检查令牌是否可续订，并设置一个 goroutine 来管理续订生命周期。
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
		vc.logger.Warn(ctx, "Token is not renewable, skipping renewal setup")
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

	vc.logger.Info(ctx, "Token renewal started")
	return nil
}

// renewalLoop is the core logic for the background token renewal goroutine.
// It listens on channels for renewal events, completion, or cancellation.
// renewalLoop 是后台令牌续订 goroutine 的核心逻辑。
// 它侦听通道以获取续订事件、完成或取消。
func (vc *VaultClient) renewalLoop(ctx context.Context, renewer *vault.Renewer) {
	go renewer.Renew()
	defer renewer.Stop()

	for {
		select {
		case err := <-renewer.DoneCh():
			if err != nil {
				vc.logger.Error(ctx, "Token renewal failed", err)
			}
			vc.logger.Info(ctx, "Token renewal stopped")
			return

		case renewal := <-renewer.RenewCh():
			vc.logger.Debug(ctx, "Token renewed",
				logger.Int("lease_duration", renewal.Secret.LeaseDuration),
			)

		case <-ctx.Done():
			vc.logger.Info(ctx, "Token renewal cancelled")
			return
		}
	}
}

// StopTokenRenewal gracefully stops the automatic token renewal process.
// StopTokenRenewal 优雅地停止自动令牌续订过程。
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

	vc.logger.Info(context.Background(), "Token renewal stopped")
}

// WriteSecret creates or updates a secret in Vault's KVv2 secrets engine.
// The provided data will be stored at the specified path.
// WriteSecret 在 Vault 的 KVv2 秘密引擎中创建或更新一个秘密。
// 提供的数据将存储在指定的路径下。
func (vc *VaultClient) WriteSecret(ctx context.Context, path string, data SecretData) error {
	// For KV v2, wrap data in "data" field
	wrappedData := map[string]interface{}{
		"data": data,
	}

	_, err := vc.client.Logical().WriteWithContext(ctx, path, wrappedData)
	if err != nil {
		vc.logger.Error(ctx, "Failed to write secret", err,
			logger.String("path", path),
		)
		return fmt.Errorf("failed to write secret: %w", err)
	}

	vc.logger.Debug(ctx, "Secret written", logger.String("path", path))
	return nil
}

// ReadSecret retrieves a secret from Vault's KVv2 secrets engine.
// It returns the secret data as a map or an error if not found.
// ReadSecret 从 Vault 的 KVv2 秘密引擎中检索秘密。
// 它以 map 的形式返回秘密数据，如果未找到则返回错误。
func (vc *VaultClient) ReadSecret(ctx context.Context, path string) (SecretData, error) {
	secret, err := vc.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		vc.logger.Error(ctx, "Failed to read secret", err,
			logger.String("path", path),
		)
		return nil, fmt.Errorf("failed to read secret: %w", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", path)
	}

	// For KV v2, extract data from "data" field
	if dataRaw, ok := secret.Data["data"]; ok {
		if data, ok := dataRaw.(map[string]interface{}); ok {
			vc.logger.Debug(ctx, "Secret read", logger.String("path", path))
			return data, nil
		}
	}

	// Fallback for KV v1 or direct data access
	vc.logger.Debug(ctx, "Secret read", logger.String("path", path))
	return secret.Data, nil
}

// DeleteSecret removes a secret from the Vault KV store.
// For KVv2, this permanently deletes the current version of the secret.
// DeleteSecret 从 Vault KV 存储中删除一个秘密。
// 对于 KVv2，这将永久删除秘密的当前版本。
func (vc *VaultClient) DeleteSecret(ctx context.Context, path string) error {
	_, err := vc.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		vc.logger.Error(ctx, "Failed to delete secret", err,
			logger.String("path", path),
		)
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	vc.logger.Debug(ctx, "Secret deleted", logger.String("path", path))
	return nil
}

// ListSecrets enumerates secret keys at a given path in the KV store.
// Note: This operation requires 'list' capabilities on the Vault path.
// ListSecrets 枚举 KV 存储中给定路径下的秘密密钥。
// 注意：此操作需要对 Vault 路径具有 'list' 权限。
func (vc *VaultClient) ListSecrets(ctx context.Context, path string) ([]string, error) {
	secret, err := vc.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		vc.logger.Error(ctx, "Failed to list secrets", err,
			logger.String("path", path),
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

// Encrypt performs encryption of plaintext data using a named key in Vault's transit secrets engine.
// Encrypt 使用 Vault 的 transit 秘密引擎中的命名密钥对明文数据进行加密。
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
		vc.logger.Error(ctx, "Failed to encrypt data", err,
			logger.String("key", keyName),
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

	vc.logger.Debug(ctx, "Data encrypted",
		logger.String("key", keyName),
		logger.Int("key_version", response.KeyVersion),
	)

	return response, nil
}

// Decrypt performs decryption of ciphertext using a named key in Vault's transit secrets engine.
// Decrypt 使用 Vault 的 transit 秘密引擎中的命名密钥对密文进行解密。
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
		vc.logger.Error(ctx, "Failed to decrypt data", err,
			logger.String("key", keyName),
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

	vc.logger.Debug(ctx, "Data decrypted",
		logger.String("key", keyName),
		logger.Int("key_version", response.KeyVersion),
	)

	return response, nil
}

// GenerateDataKey creates a new data encryption key (DEK) using the transit engine.
// It returns both the plaintext version of the key and its ciphertext (encrypted by the master key).
// GenerateDataKey 使用 transit 引擎创建一个新的数据加密密钥 (DEK)。
// 它返回密钥的明文版本及其密文（由主密钥加密）。
func (vc *VaultClient) GenerateDataKey(ctx context.Context, keyName string, bits int) ([]byte, string, error) {
	path := fmt.Sprintf("transit/datakey/plaintext/%s", keyName)

	data := map[string]interface{}{
		"bits": bits,
	}

	secret, err := vc.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		vc.logger.Error(ctx, "Failed to generate data key", err,
			logger.String("key", keyName),
			logger.Int("bits", bits),
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

	vc.logger.Debug(ctx, "Data key generated",
		logger.String("key", keyName),
		logger.Int("bits", bits),
	)

	return plaintext, ciphertext, nil
}

// GetDynamicDBCredentials generates dynamic, short-lived database credentials from a configured role.
// GetDynamicDBCredentials 从已配置的角色生成动态的、短暂的数据库凭据。
func (vc *VaultClient) GetDynamicDBCredentials(ctx context.Context, role string) (*DynamicCredentials, error) {
	path := fmt.Sprintf("database/creds/%s", role)

	secret, err := vc.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		vc.logger.Error(ctx, "Failed to get dynamic DB credentials", err,
			logger.String("role", role),
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

	vc.logger.Debug(ctx, "Dynamic DB credentials generated",
		logger.String("role", role),
		logger.String("username", username),
		logger.Duration("lease_duration", creds.LeaseDuration),
	)

	return creds, nil
}

// RenewLease extends the validity of a secret's lease.
// This is used for dynamic credentials and other leased secrets.
// RenewLease 延长秘密租约的有效期。
// 这用于动态凭据和其他租用秘密。
func (vc *VaultClient) RenewLease(ctx context.Context, leaseID string, increment time.Duration) (time.Duration, error) {
	incrementSeconds := int(increment.Seconds())

	secret, err := vc.client.Sys().RenewWithContext(ctx, leaseID, incrementSeconds)
	if err != nil {
		vc.logger.Error(ctx, "Failed to renew lease", err,
			logger.String("lease_id", leaseID),
		)
		return 0, fmt.Errorf("failed to renew lease: %w", err)
	}

	duration := time.Duration(secret.LeaseDuration) * time.Second

	vc.logger.Debug(ctx, "Lease renewed",
		logger.String("lease_id", leaseID),
		logger.Duration("duration", duration),
	)

	return duration, nil
}

// RevokeLease immediately invalidates a secret's lease.
// After revocation, the secret can no longer be used.
// RevokeLease 立即作废一个秘密的租约。
// 撤销后，该秘密将无法再使用。
func (vc *VaultClient) RevokeLease(ctx context.Context, leaseID string) error {
	err := vc.client.Sys().RevokeWithContext(ctx, leaseID)
	if err != nil {
		vc.logger.Error(ctx, "Failed to revoke lease", err,
			logger.String("lease_id", leaseID),
		)
		return fmt.Errorf("failed to revoke lease: %w", err)
	}

	vc.logger.Debug(ctx, "Lease revoked", logger.String("lease_id", leaseID))
	return nil
}

// Health checks the status of the Vault server.
// It returns true if the server is initialized and unsealed.
// Health 检查 Vault 服务器的状态。
// 如果服务器已初始化且未封印，则返回 true。
func (vc *VaultClient) Health(ctx context.Context) (bool, error) {
	health, err := vc.client.Sys().HealthWithContext(ctx)
	if err != nil {
		vc.logger.Error(ctx, "Health check failed", err)
		return false, err
	}

	isHealthy := health.Initialized && !health.Sealed

	vc.logger.Debug(ctx, "Health check completed",
		logger.Bool("initialized", health.Initialized),
		logger.Bool("sealed", health.Sealed),
		logger.Bool("healthy", isHealthy),
	)

	return isHealthy, nil
}

// Close gracefully shuts down the Vault client, stopping any background processes like token renewal.
// It should be called when the application is shutting down.
// Close 优雅地关闭 Vault 客户端，停止任何后台进程，如令牌续订。
// 应在应用程序关闭时调用此方法。
func (vc *VaultClient) Close() error {
	vc.StopTokenRenewal()
	vc.logger.Info(context.Background(), "Vault client closed")
	return nil
}
