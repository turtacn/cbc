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

// Config holds Redis connection configuration parameters.
type Config struct {
	// Mode specifies deployment mode (standalone, cluster, sentinel)
	Mode ConnectionMode `json:"mode" yaml:"mode"`

	// Standalone configuration
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Password string `json:"password" yaml:"password"`
	DB       int    `json:"db" yaml:"db"`

	// Cluster configuration
	ClusterAddrs []string `json:"cluster_addrs" yaml:"cluster_addrs"`

	// Sentinel configuration
	SentinelAddrs  []string `json:"sentinel_addrs" yaml:"sentinel_addrs"`
	SentinelMaster string   `json:"sentinel_master" yaml:"sentinel_master"`

	// Connection pool settings
	PoolSize     int           `json:"pool_size" yaml:"pool_size"`
	MinIdleConns int           `json:"min_idle_conns" yaml:"min_idle_conns"`
	MaxIdleTime  time.Duration `json:"max_idle_time" yaml:"max_idle_time"`
	MaxLifetime  time.Duration `json:"max_lifetime" yaml:"max_lifetime"`

	// Timeout settings
	DialTimeout  time.Duration `json:"dial_timeout" yaml:"dial_timeout"`
	ReadTimeout  time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout"`

	// TLS configuration
	EnableTLS      bool   `json:"enable_tls" yaml:"enable_tls"`
	TLSSkipVerify  bool   `json:"tls_skip_verify" yaml:"tls_skip_verify"`
	TLSCertFile    string `json:"tls_cert_file" yaml:"tls_cert_file"`
	TLSKeyFile     string `json:"tls_key_file" yaml:"tls_key_file"`
	TLSCACertFile  string `json:"tls_ca_cert_file" yaml:"tls_ca_cert_file"`

	// Retry settings
	MaxRetries      int           `json:"max_retries" yaml:"max_retries"`
	MinRetryBackoff time.Duration `json:"min_retry_backoff" yaml:"min_retry_backoff"`
	MaxRetryBackoff time.Duration `json:"max_retry_backoff" yaml:"max_retry_backoff"`
}

// RedisConnection manages Redis client lifecycle and health monitoring.
type RedisConnection struct {
	config        *Config
	client        redis.UniversalClient
	logger        logger.Logger
	isInitialized bool
}

// NewRedisConnection creates a new Redis connection manager instance.
//
// Parameters:
//   - config: Redis configuration
//   - log: Logger instance
//
// Returns:
//   - *RedisConnection: Initialized connection manager
func NewRedisConnection(config *Config, log logger.Logger) *RedisConnection {
	return &RedisConnection{
		config:        config,
		logger:        log,
		isInitialized: false,
	}
}

// Connect establishes Redis connection based on configured mode.
// It initializes connection pool and validates connectivity.
//
// Returns:
//   - error: Connection establishment error if any
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

// connectStandalone creates standalone Redis client.
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

// connectCluster creates Redis cluster client.
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

// connectSentinel creates Redis sentinel client for high availability.
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

// buildTLSConfig constructs TLS configuration for secure connections.
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

// setDefaults sets default configuration values if not specified.
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

// GetClient returns the Redis client instance.
// It returns nil if connection is not initialized.
//
// Returns:
//   - redis.UniversalClient: Redis client instance
func (rc *RedisConnection) GetClient() redis.UniversalClient {
	if !rc.isInitialized {
		return nil
	}
	return rc.client
}

// Ping checks Redis server connectivity.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - error: Connectivity check error if any
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

// HealthCheck performs comprehensive health check on Redis connection.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - map[string]interface{}: Health status details
//   - error: Health check error if any
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

// GetPoolStats returns current connection pool statistics.
//
// Returns:
//   - *redis.PoolStats: Pool statistics
func (rc *RedisConnection) GetPoolStats() *redis.PoolStats {
	if !rc.isInitialized {
		return nil
	}

	stats := rc.client.PoolStats()
	return stats
}

// Close gracefully closes Redis connection and releases resources.
//
// Returns:
//   - error: Closure error if any
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

// IsConnected returns whether Redis connection is active.
//
// Returns:
//   - bool: True if connected and healthy
func (rc *RedisConnection) IsConnected() bool {
	if !rc.isInitialized {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return rc.client.Ping(ctx).Err() == nil
}

// Reconnect attempts to re-establish Redis connection.
//
// Returns:
//   - error: Reconnection error if any
func (rc *RedisConnection) Reconnect() error {
	rc.logger.Info(context.Background(), "Attempting to reconnect to Redis")

	// Close existing connection if any
	if rc.isInitialized {
		_ = rc.Close()
	}

	// Re-establish connection
	return rc.Connect()
}

// FlushDB flushes all keys from the current database.
// WARNING: This is a destructive operation!
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - error: Flush operation error if any
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

// GetConfig returns a copy of the current configuration.
//
// Returns:
//   - *Config: Configuration copy
func (rc *RedisConnection) GetConfig() *Config {
	configCopy := *rc.config
	return &configCopy
}

// WaitForConnection blocks until Redis connection is established or timeout occurs.
//
// Parameters:
//   - ctx: Context for timeout control
//   - checkInterval: Interval between connection checks
//
// Returns:
//   - error: Timeout or connection error
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
