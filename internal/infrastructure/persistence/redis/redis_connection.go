// Package redis provides Redis connection management and client initialization.
// It supports standalone, cluster, and sentinel deployment modes with connection pooling.
package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/turtacn/cbc/pkg/logger"
)

var _ RedisConnectionManager = (*RedisConnection)(nil)

// ConnectionMode defines Redis deployment mode
type ConnectionMode string

const (
	// ModeStandalone represents single Redis instance
	ModeStandalone ConnectionMode = "standalone"
	// ModeCluster represents Redis cluster mode
	ModeCluster ConnectionMode = "cluster"
	// ModeSentinel represents Redis sentinel mode for high availability
	ModeSentinel ConnectionMode = "sentinel"
)

// Config holds all necessary configuration parameters for establishing a Redis connection.
// It supports standalone, cluster, and sentinel modes, along with TLS and connection pooling options.
// Config 保存建立 Redis 连接所需的所有必要配置参数。
// 它支持独立、集群和哨兵模式，以及 TLS 和连接池选项。
type Config struct {
	// Mode specifies the Redis deployment mode (standalone, cluster, sentinel).
	// Mode 指定 Redis 的部署模式（standalone、cluster、sentinel）。
	Mode ConnectionMode `json:"mode" yaml:"mode"`

	// Host is the address for a standalone Redis instance.
	// Host 是独立 Redis 实例的地址。
	Host string `json:"host" yaml:"host"`
	// Port is the port for a standalone Redis instance.
	// Port 是独立 Redis 实例的端口。
	Port int `json:"port" yaml:"port"`
	// Password is the authentication password for Redis.
	// Password 是 Redis 的身份验证密码。
	Password string `json:"password" yaml:"password"`
	// DB is the database number to select for a standalone connection.
	// DB 是为独立连接选择的数据库编号。
	DB int `json:"db" yaml:"db"`

	// ClusterAddrs is a list of host:port addresses for Redis Cluster nodes.
	// ClusterAddrs 是 Redis 集群节点的主机:端口地址列表。
	ClusterAddrs []string `json:"cluster_addrs" yaml:"cluster_addrs"`

	// SentinelAddrs is a list of host:port addresses for Redis Sentinel nodes.
	// SentinelAddrs 是 Redis 哨兵节点的主机:端口地址列表。
	SentinelAddrs []string `json:"sentinel_addrs" yaml:"sentinel_addrs"`
	// SentinelMaster is the name of the master to look up via Sentinel.
	// SentinelMaster 是通过哨兵查找的主节点名称。
	SentinelMaster string `json:"sentinel_master" yaml:"sentinel_master"`

	// PoolSize is the maximum number of socket connections.
	// PoolSize 是套接字连接的最大数量。
	PoolSize int `json:"pool_size" yaml:"pool_size"`
	// MinIdleConns is the minimum number of idle connections to maintain.
	// MinIdleConns 是要维护的最小空闲连接数。
	MinIdleConns int `json:"min_idle_conns" yaml:"min_idle_conns"`
	// MaxIdleTime is the maximum amount of time a connection may be idle before being closed.
	// MaxIdleTime 是连接在关闭前可能空闲的最长时间。
	MaxIdleTime time.Duration `json:"max_idle_time" yaml:"max_idle_time"`
	// MaxLifetime is the maximum amount of time a connection may be reused.
	// MaxLifetime 是连接可被重用的最长时间。
	MaxLifetime time.Duration `json:"max_lifetime" yaml:"max_lifetime"`

	// DialTimeout is the timeout for establishing new connections.
	// DialTimeout 是建立新连接的超时时间。
	DialTimeout time.Duration `json:"dial_timeout" yaml:"dial_timeout"`
	// ReadTimeout is the timeout for read operations.
	// ReadTimeout 是读取操作的超时时间。
	ReadTimeout time.Duration `json:"read_timeout" yaml:"read_timeout"`
	// WriteTimeout is the timeout for write operations.
	// WriteTimeout 是写入操作的超时时间。
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout"`

	// EnableTLS specifies whether to use TLS for the connection.
	// EnableTLS 指定是否为连接使用 TLS。
	EnableTLS bool `json:"enable_tls" yaml:"enable_tls"`
	// TLSSkipVerify disables server certificate verification (not recommended for production).
	// TLSSkipVerify 禁用服务器证书验证（不建议在生产环境中使用）。
	TLSSkipVerify bool `json:"tls_skip_verify" yaml:"tls_skip_verify"`
	// TLSCertFile is the path to the client certificate file.
	// TLSCertFile 是客户端证书文件的路径。
	TLSCertFile string `json:"tls_cert_file" yaml:"tls_cert_file"`
	// TLSKeyFile is the path to the client private key file.
	// TLSKeyFile 是客户端私钥文件的路径。
	TLSKeyFile string `json:"tls_key_file" yaml:"tls_key_file"`
	// TLSCACertFile is the path to the CA certificate file.
	// TLSCACertFile 是 CA 证书文件的路径。
	TLSCACertFile string `json:"tls_ca_cert_file" yaml:"tls_ca_cert_file"`

	// MaxRetries is the maximum number of retries before giving up on a command.
	// MaxRetries 是放弃命令前的最大重试次数。
	MaxRetries int `json:"max_retries" yaml:"max_retries"`
	// MinRetryBackoff is the minimum backoff time between retries.
	// MinRetryBackoff 是重试之间的最小退避时间。
	MinRetryBackoff time.Duration `json:"min_retry_backoff" yaml:"min_retry_backoff"`
	// MaxRetryBackoff is the maximum backoff time between retries.
	// MaxRetryBackoff 是重试之间的最大退避时间。
	MaxRetryBackoff time.Duration `json:"max_retry_backoff" yaml:"max_retry_backoff"`
}

// RedisConnection manages the lifecycle of a Redis client, including connection, disconnection, and health monitoring.
// RedisConnection 管理 Redis 客户端的生命周期，包括连接、断开连接和健康监控。
type RedisConnection struct {
	config        *Config
	client        redis.UniversalClient
	logger        logger.Logger
	isInitialized bool
}

// NewRedisConnection creates a new, uninitialized Redis connection manager.
// The `Connect` method must be called to establish the actual connection.
// NewRedisConnection 创建一个新的、未初始化的 Redis 连接管理器。
// 必须调用 `Connect` 方法来建立实际的连接。
func NewRedisConnection(config *Config, log logger.Logger) *RedisConnection {
	return &RedisConnection{
		config:        config,
		logger:        log,
		isInitialized: false,
	}
}

// Connect establishes a connection to Redis based on the configured mode.
// It initializes the appropriate client (standalone, cluster, or sentinel) and verifies connectivity with a PING command.
// Connect 根据配置的模式建立到 Redis 的连接。
// 它会初始化适当的客户端（独立、集群或哨兵）并使用 PING 命令验证连接性。
func (rc *RedisConnection) Connect() error {
	if rc.isInitialized {
		rc.logger.Warn(context.Background(), "Redis connection already initialized")
		return nil
	}

	// Set default values
	rc.setDefaults()

	var client redis.UniversalClient
	var err error

	switch rc.config.Mode {
	case ModeStandalone:
		client, err = rc.connectStandalone()
	case ModeCluster:
		client, err = rc.connectCluster()
	case ModeSentinel:
		client, err = rc.connectSentinel()
	default:
		return fmt.Errorf("unsupported Redis mode: %s", rc.config.Mode)
	}

	if err != nil {
		rc.logger.Error(context.Background(), "Failed to establish Redis connection", err,
			logger.String("mode", string(rc.config.Mode)),
		)
		return fmt.Errorf("redis connection failed: %w", err)
	}

	rc.client = client

	// Verify connection with ping
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rc.client.Ping(ctx).Err(); err != nil {
		rc.logger.Error(ctx, "Redis ping failed", err)
		_ = rc.client.Close()
		return fmt.Errorf("redis ping failed: %w", err)
	}

	rc.isInitialized = true
	rc.logger.Info(ctx, "Redis connection established successfully",
		logger.String("mode", string(rc.config.Mode)),
		logger.Int("pool_size", rc.config.PoolSize),
	)

	return nil
}

// connectStandalone creates a client for a single Redis instance.
// connectStandalone 为单个 Redis 实例创建客户端。
func (rc *RedisConnection) connectStandalone() (redis.UniversalClient, error) {
	addr := fmt.Sprintf("%s:%d", rc.config.Host, rc.config.Port)

	opts := &redis.Options{
		Addr:     addr,
		Password: rc.config.Password,
		DB:       rc.config.DB,

		// Pool settings
		PoolSize:        rc.config.PoolSize,
		MinIdleConns:    rc.config.MinIdleConns,
		ConnMaxIdleTime: rc.config.MaxIdleTime,
		ConnMaxLifetime: rc.config.MaxLifetime,

		// Timeout settings
		DialTimeout:  rc.config.DialTimeout,
		ReadTimeout:  rc.config.ReadTimeout,
		WriteTimeout: rc.config.WriteTimeout,

		// Retry settings
		MaxRetries:      rc.config.MaxRetries,
		MinRetryBackoff: rc.config.MinRetryBackoff,
		MaxRetryBackoff: rc.config.MaxRetryBackoff,
	}

	// Configure TLS if enabled
	if rc.config.EnableTLS {
		tlsConfig, err := rc.buildTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		opts.TLSConfig = tlsConfig
	}

	rc.logger.Info(context.Background(), "Connecting to Redis standalone",
		logger.String("addr", addr),
		logger.Int("db", rc.config.DB),
	)

	return redis.NewClient(opts), nil
}

// connectCluster creates a client for a Redis Cluster deployment.
// connectCluster 为 Redis 集群部署创建客户端。
func (rc *RedisConnection) connectCluster() (redis.UniversalClient, error) {
	if len(rc.config.ClusterAddrs) == 0 {
		return nil, fmt.Errorf("cluster addresses not configured")
	}

	opts := &redis.ClusterOptions{
		Addrs:    rc.config.ClusterAddrs,
		Password: rc.config.Password,

		// Pool settings
		PoolSize:        rc.config.PoolSize,
		MinIdleConns:    rc.config.MinIdleConns,
		ConnMaxIdleTime: rc.config.MaxIdleTime,
		ConnMaxLifetime: rc.config.MaxLifetime,

		// Timeout settings
		DialTimeout:  rc.config.DialTimeout,
		ReadTimeout:  rc.config.ReadTimeout,
		WriteTimeout: rc.config.WriteTimeout,

		// Retry settings
		MaxRetries:      rc.config.MaxRetries,
		MinRetryBackoff: rc.config.MinRetryBackoff,
		MaxRetryBackoff: rc.config.MaxRetryBackoff,
	}

	// Configure TLS if enabled
	if rc.config.EnableTLS {
		tlsConfig, err := rc.buildTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		opts.TLSConfig = tlsConfig
	}

	rc.logger.Info(context.Background(), "Connecting to Redis cluster",
		logger.Any("addrs", rc.config.ClusterAddrs),
	)

	return redis.NewClusterClient(opts), nil
}

// connectSentinel creates a client for a Redis deployment managed by Sentinel for high availability.
// connectSentinel 为由 Sentinel 管理的 Redis 部署创建客户端以实现高可用性。
func (rc *RedisConnection) connectSentinel() (redis.UniversalClient, error) {
	if len(rc.config.SentinelAddrs) == 0 {
		return nil, fmt.Errorf("sentinel addresses not configured")
	}
	if rc.config.SentinelMaster == "" {
		return nil, fmt.Errorf("sentinel master name not configured")
	}

	opts := &redis.FailoverOptions{
		MasterName:    rc.config.SentinelMaster,
		SentinelAddrs: rc.config.SentinelAddrs,
		Password:      rc.config.Password,
		DB:            rc.config.DB,

		// Pool settings
		PoolSize:        rc.config.PoolSize,
		MinIdleConns:    rc.config.MinIdleConns,
		ConnMaxIdleTime: rc.config.MaxIdleTime,
		ConnMaxLifetime: rc.config.MaxLifetime,

		// Timeout settings
		DialTimeout:  rc.config.DialTimeout,
		ReadTimeout:  rc.config.ReadTimeout,
		WriteTimeout: rc.config.WriteTimeout,

		// Retry settings
		MaxRetries:      rc.config.MaxRetries,
		MinRetryBackoff: rc.config.MinRetryBackoff,
		MaxRetryBackoff: rc.config.MaxRetryBackoff,
	}

	// Configure TLS if enabled
	if rc.config.EnableTLS {
		tlsConfig, err := rc.buildTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		opts.TLSConfig = tlsConfig
	}

	rc.logger.Info(context.Background(), "Connecting to Redis sentinel",
		logger.String("master", rc.config.SentinelMaster),
		logger.Any("sentinels", rc.config.SentinelAddrs),
	)

	return redis.NewFailoverClient(opts), nil
}

// buildTLSConfig constructs a `*tls.Config` object from the Redis configuration.
// Note: This is a simplified implementation. A production version should handle loading certificates from files.
// buildTLSConfig 根据 Redis 配置构造一个 `*tls.Config` 对象。
// 注意：这是一个简化的实现。生产版本应处理从文件加载证书。
func (rc *RedisConnection) buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: rc.config.TLSSkipVerify,
	}

	// Load certificates if provided
	if rc.config.TLSCertFile != "" && rc.config.TLSKeyFile != "" {
		// Certificate loading would be implemented here
		// For now, using basic config
		rc.logger.Info(context.Background(), "TLS enabled for Redis connection")
	}

	return tlsConfig, nil
}

// setDefaults applies sensible default values to the configuration if they are not explicitly provided.
// setDefaults 为配置应用合理的默认值（如果未明确提供）。
func (rc *RedisConnection) setDefaults() {
	if rc.config.Mode == "" {
		rc.config.Mode = ModeStandalone
	}
	if rc.config.Host == "" {
		rc.config.Host = "localhost"
	}
	if rc.config.Port == 0 {
		rc.config.Port = 6379
	}
	if rc.config.PoolSize == 0 {
		rc.config.PoolSize = 10
	}
	if rc.config.MinIdleConns == 0 {
		rc.config.MinIdleConns = 2
	}
	if rc.config.MaxIdleTime == 0 {
		rc.config.MaxIdleTime = 5 * time.Minute
	}
	if rc.config.MaxLifetime == 0 {
		rc.config.MaxLifetime = 1 * time.Hour
	}
	if rc.config.DialTimeout == 0 {
		rc.config.DialTimeout = 5 * time.Second
	}
	if rc.config.ReadTimeout == 0 {
		rc.config.ReadTimeout = 3 * time.Second
	}
	if rc.config.WriteTimeout == 0 {
		rc.config.WriteTimeout = 3 * time.Second
	}
	if rc.config.MaxRetries == 0 {
		rc.config.MaxRetries = 3
	}
	if rc.config.MinRetryBackoff == 0 {
		rc.config.MinRetryBackoff = 8 * time.Millisecond
	}
	if rc.config.MaxRetryBackoff == 0 {
		rc.config.MaxRetryBackoff = 512 * time.Millisecond
	}
}

// GetClient returns the underlying `redis.UniversalClient`.
// This allows direct access to the Redis client for operations not covered by a higher-level manager.
// It returns nil if the connection has not been initialized.
// GetClient 返回底层的 `redis.UniversalClient`。
// 这允许直接访问 Redis 客户端以执行更高级别管理器未涵盖的操作。
// 如果连接尚未初始化，则返回 nil。
func (rc *RedisConnection) GetClient() redis.UniversalClient {
	if !rc.isInitialized {
		return nil
	}
	return rc.client
}

// Ping verifies that the connection to the Redis server is alive.
// Ping 验证与 Redis 服务器的连接是否有效。
func (rc *RedisConnection) Ping(ctx context.Context) error {
	if !rc.isInitialized {
		return fmt.Errorf("redis connection not initialized")
	}

	if err := rc.client.Ping(ctx).Err(); err != nil {
		rc.logger.Error(ctx, "Redis ping failed", err)
		return err
	}

	return nil
}

// HealthCheck provides a detailed status of the Redis connection, including latency and pool statistics.
// It's suitable for use in application health endpoints.
// HealthCheck 提供 Redis 连接的详细状态，包括延迟和连接池统计信息。
// 它适用于应用程序的健康端点。
func (rc *RedisConnection) HealthCheck(ctx context.Context) (map[string]interface{}, error) {
	if !rc.isInitialized {
		return nil, fmt.Errorf("redis connection not initialized")
	}

	health := make(map[string]interface{})

	// Check connectivity
	start := time.Now()
	err := rc.client.Ping(ctx).Err()
	latency := time.Since(start)

	health["connected"] = err == nil
	health["latency_ms"] = latency.Milliseconds()

	if err != nil {
		health["error"] = err.Error()
		return health, err
	}

	// Get pool statistics
	stats := rc.client.PoolStats()
	health["pool_hits"] = stats.Hits
	health["pool_misses"] = stats.Misses
	health["pool_timeouts"] = stats.Timeouts
	health["total_conns"] = stats.TotalConns
	health["idle_conns"] = stats.IdleConns
	health["stale_conns"] = stats.StaleConns

	// Get server info
	_, err = rc.client.Info(ctx, "server", "memory", "stats").Result()
	if err == nil {
		health["server_info"] = "available"
	}

	rc.logger.Debug(ctx, "Redis health check completed",
		logger.Any("connected", health["connected"]),
		logger.Any("latency_ms", health["latency_ms"]),
		logger.Any("total_conns", health["total_conns"]),
	)

	return health, nil
}

// GetPoolStats returns a snapshot of the connection pool's current statistics.
// GetPoolStats 返回连接池当前统计信息的快照。
func (rc *RedisConnection) GetPoolStats() *redis.PoolStats {
	if !rc.isInitialized {
		return nil
	}

	stats := rc.client.PoolStats()
	return stats
}

// Close gracefully terminates the connection to the Redis server and releases all associated resources.
// It should be called during application shutdown.
// Close 优雅地终止与 Redis 服务器的连接并释放所有相关资源。
// 应在应用程序关闭期间调用它。
func (rc *RedisConnection) Close() error {
	if !rc.isInitialized {
		rc.logger.Warn(context.Background(), "Redis connection not initialized, nothing to close")
		return nil
	}

	if err := rc.client.Close(); err != nil {
		rc.logger.Error(context.Background(), "Failed to close Redis connection", err)
		return err
	}

	rc.isInitialized = false
	rc.logger.Info(context.Background(), "Redis connection closed successfully")
	return nil
}

// IsConnected returns a boolean indicating whether the client is currently connected to Redis.
// It performs a quick PING to check the connection status.
// IsConnected 返回一个布尔值，指示客户端当前是否已连接到 Redis。
// 它执行快速 PING 来检查连接状态。
func (rc *RedisConnection) IsConnected() bool {
	if !rc.isInitialized {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return rc.client.Ping(ctx).Err() == nil
}

// Reconnect attempts to close the existing connection (if any) and establish a new one.
// This can be used to recover from certain types of network errors.
// Reconnect 尝试关闭现有连接（如果有）并建立一个新连接。
// 这可用于从某些类型的网络错误中恢复。
func (rc *RedisConnection) Reconnect() error {
	rc.logger.Info(context.Background(), "Attempting to reconnect to Redis")

	// Close existing connection if any
	if rc.isInitialized {
		_ = rc.Close()
	}

	// Re-establish connection
	return rc.Connect()
}

// FlushDB issues a `FLUSHDB` command to the current database, deleting all keys.
// This is a destructive operation and should be used with extreme caution, primarily in testing environments.
// FlushDB 向当前数据库发出 `FLUSHDB` 命令，删除所有密钥。
// 这是一个破坏性操作，应极其谨慎地使用，主要用于测试环境。
func (rc *RedisConnection) FlushDB(ctx context.Context) error {
	if !rc.isInitialized {
		return fmt.Errorf("redis connection not initialized")
	}

	if err := rc.client.FlushDB(ctx).Err(); err != nil {
		rc.logger.Error(ctx, "Failed to flush Redis database", err)
		return err
	}

	rc.logger.Warn(ctx, "Redis database flushed successfully")
	return nil
}

// GetConfig returns a copy of the configuration used by the connection manager.
// This is useful for inspection and debugging.
// GetConfig 返回连接管理器使用的配置的副本。
// 这对于检查和调试很有用。
func (rc *RedisConnection) GetConfig() *Config {
	configCopy := *rc.config
	return &configCopy
}

// WaitForConnection blocks execution until a connection to Redis is successfully established.
// It checks for connectivity at a specified interval and respects the context deadline.
// WaitForConnection 会阻塞执行，直到成功建立与 Redis 的连接。
// 它会按指定的时间间隔检查连接性，并遵守上下文的截止日期。
func (rc *RedisConnection) WaitForConnection(ctx context.Context, checkInterval time.Duration) error {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if rc.IsConnected() {
				rc.logger.Info(ctx, "Redis connection established")
				return nil
			}
			rc.logger.Debug(ctx, "Waiting for Redis connection...")
		}
	}
}
