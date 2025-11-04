// Package config defines the service configuration structure.
package config

import (
	"fmt"
	"time"

	"github.com/turtacn/cbc/pkg/constants"
)

// Config is the main configuration structure for the service.
type Config struct {
	Server        ServerConfig        `mapstructure:"server"`
	Database      DatabaseConfig      `mapstructure:"database"`
	Redis         RedisConfig         `mapstructure:"redis"`
	Vault         VaultConfig         `mapstructure:"vault"`
	JWT           JWTConfig           `mapstructure:"jwt"`
	RateLimit     RateLimitConfig     `mapstructure:"rate_limit"`
	Idempotency   IdempotencyConfig   `mapstructure:"idempotency"`
	Log           LogConfig           `mapstructure:"log"`
	Observability ObservabilityConfig `mapstructure:"observability"`
	Kafka         KafkaConfig         `mapstructure:"kafka"`
	OAuth         OAuthConfig         `mapstructure:"oauth"`
}

// OAuthConfig holds settings for OAuth 2.0 features, including Device Authorization Grant.
type OAuthConfig struct {
	DeviceAuthExpiresIn time.Duration `mapstructure:"device_auth_expires_in" env:"CBC_AUTH_OAUTH_DEVICE_AUTH_EXPIRES_IN" default:"600s"`
	DeviceAuthInterval  time.Duration `mapstructure:"device_auth_interval" env:"CBC_AUTH_OAUTH_DEVICE_AUTH_INTERVAL" default:"5s"`
	VerificationURI     string        `mapstructure:"verification_uri" env:"CBC_AUTH_OAUTH_VERIFICATION_URI" default:"https://example.com/verify"`
	DevVerifyAPIEnabled bool          `mapstructure:"dev_verify_api_enabled" env:"CBC_AUTH_OAUTH_DEV_VERIFY_API_ENABLED" default:"false"`
}

// KafkaConfig holds Kafka settings for the audit producer.
type KafkaConfig struct {
	Brokers       []string      `mapstructure:"brokers" env:"CBC_AUTH_KAFKA_BROKERS" default:"localhost:9092"`
	AuditTopic    string        `mapstructure:"audit_topic" env:"CBC_AUTH_KAFKA_AUDIT_TOPIC" default:"cbc-audit-logs"`
	WriteTimeout  time.Duration `mapstructure:"write_timeout" env:"CBC_AUTH_KAFKA_WRITE_TIMEOUT" default:"10s"`
	ReadTimeout   time.Duration `mapstructure:"read_timeout" env:"CBC_AUTH_KAFKA_READ_TIMEOUT" default:"10s"`
	RequiredAcks  int           `mapstructure:"required_acks" env:"CBC_AUTH_KAFKA_REQUIRED_ACKS" default:"-1"` // -1 for all ISRs
	MaxMessageBytes int         `mapstructure:"max_message_bytes" env:"CBC_AUTH_KAFKA_MAX_MESSAGE_BYTES" default:"1048576"`
	BatchSize     int           `mapstructure:"batch_size" env:"CBC_AUTH_KAFKA_BATCH_SIZE" default:"100"`
	BatchTimeout  time.Duration `mapstructure:"batch_timeout" env:"CBC_AUTH_KAFKA_BATCH_TIMEOUT" default:"1s"`
}

// ServerConfig holds HTTP/gRPC server settings.
type ServerConfig struct {
	HTTPHost         string        `mapstructure:"http_host" env:"CBC_AUTH_HTTP_HOST" default:"0.0.0.0"`
	HTTPPort         int           `mapstructure:"http_port" env:"CBC_AUTH_HTTP_PORT" default:"8080"`
	HTTPReadTimeout  time.Duration `mapstructure:"http_read_timeout" env:"CBC_AUTH_HTTP_READ_TIMEOUT" default:"30s"`
	HTTPWriteTimeout time.Duration `mapstructure:"http_write_timeout" env:"CBC_AUTH_HTTP_WRITE_TIMEOUT" default:"30s"`
	HTTPIdleTimeout  time.Duration `mapstructure:"http_idle_timeout" env:"CBC_AUTH_HTTP_IDLE_TIMEOUT" default:"120s"`

	GRPCHost              string        `mapstructure:"grpc_host" env:"CBC_AUTH_GRPC_HOST" default:"0.0.0.0"`
	GRPCPort              int           `mapstructure:"grpc_port" env:"CBC_AUTH_GRPC_PORT" default:"50051"`
	GRPCMaxConnectionIdle time.Duration `mapstructure:"grpc_max_connection_idle" env:"CBC_AUTH_GRPC_MAX_CONNECTION_IDLE" default:"5m"`
	GRPCMaxConnectionAge  time.Duration `mapstructure:"grpc_max_connection_age" env:"CBC_AUTH_GRPC_MAX_CONNECTION_AGE" default:"30m"`
	GRPCKeepAliveTime     time.Duration `mapstructure:"grpc_keepalive_time" env:"CBC_AUTH_GRPC_KEEPALIVE_TIME" default:"2h"`
	GRPCKeepAliveTimeout  time.Duration `mapstructure:"grpc_keepalive_timeout" env:"CBC_AUTH_GRPC_KEEPALIVE_TIMEOUT" default:"20s"`

	TLS             TLSConfig     `mapstructure:"tls"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout" env:"CBC_AUTH_SHUTDOWN_TIMEOUT" default:"30s"`
	IssuerURL       string        `mapstructure:"issuer_url" env:"CBC_AUTH_ISSUER_URL" default:"http://localhost:8080"`
}

// TLSConfig holds TLS/mTLS settings.
type TLSConfig struct {
	Enabled      bool   `mapstructure:"enabled" env:"CBC_AUTH_TLS_ENABLED" default:"false"`
	CertFile     string `mapstructure:"cert_file" env:"CBC_AUTH_TLS_CERT_FILE"`
	KeyFile      string `mapstructure:"key_file" env:"CBC_AUTH_TLS_KEY_FILE"`
	ClientCAFile string `mapstructure:"client_ca_file" env:"CBC_AUTH_TLS_CLIENT_CA_FILE"`
}

// DatabaseConfig holds PostgreSQL settings.
type DatabaseConfig struct {
	DSN               string        `mapstructure:"dsn" env:"PG_DSN"`
	Host              string        `mapstructure:"host" env:"CBC_AUTH_DB_HOST" default:"localhost"`
	Port              int           `mapstructure:"port" env:"CBC_AUTH_DB_PORT" default:"5432"`
	User              string        `mapstructure:"user" env:"CBC_AUTH_DB_USER" default:"cbc_auth"`
	Password          string        `mapstructure:"password" env:"CBC_AUTH_DB_PASSWORD"`
	Database          string        `mapstructure:"database" env:"CBC_AUTH_DB_NAME" default:"cbc_auth_db"`
	SSLMode           string        `mapstructure:"ssl_mode" env:"CBC_AUTH_DB_SSL_MODE" default:"require"`
	MaxConns          int32         `mapstructure:"max_conns" env:"CBC_AUTH_DB_MAX_CONNS" default:"100"`
	MinConns          int32         `mapstructure:"min_conns" env:"CBC_AUTH_DB_MIN_CONNS" default:"10"`
	MaxConnLifetime   time.Duration `mapstructure:"max_conn_lifetime" env:"CBC_AUTH_DB_MAX_CONN_LIFETIME" default:"1h"`
	MaxConnIdleTime   time.Duration `mapstructure:"max_conn_idle_time" env:"CBC_AUTH_DB_MAX_CONN_IDLE_TIME" default:"30m"`
	HealthCheckPeriod time.Duration `mapstructure:"health_check_period" env:"CBC_AUTH_DB_HEALTH_CHECK_PERIOD" default:"5m"`
	ConnTimeout       time.Duration `mapstructure:"conn_timeout" env:"CBC_AUTH_DB_CONN_TIMEOUT" default:"10s"`
}

// RedisConfig holds Redis settings.
type RedisConfig struct {
	Addr            string   `mapstructure:"addr" env:"REDIS_ADDR"`
	Address         string   `mapstructure:"address" env:"CBC_AUTH_REDIS_ADDRESS" default:"localhost:6379"`
	Password        string   `mapstructure:"password" env:"CBC_AUTH_REDIS_PASSWORD"`
	DB              int      `mapstructure:"db" env:"REDIS_DB"`
	ClusterEnabled  bool     `mapstructure:"cluster_enabled" env:"CBC_AUTH_REDIS_CLUSTER_ENABLED" default:"false"`
	ClusterAddrs    []string `mapstructure:"cluster_addrs" env:"CBC_AUTH_REDIS_CLUSTER_ADDRS"`
	PoolSize        int      `mapstructure:"pool_size" env:"CBC_AUTH_REDIS_POOL_SIZE" default:"100"`
	MinIdleConns    int      `mapstructure:"min_idle_conns" env:"CBC_AUTH_REDIS_MIN_IDLE_CONNS" default:"10"`
	MaxRetries      int      `mapstructure:"max_retries" env:"CBC_AUTH_REDIS_MAX_RETRIES" default:"3"`
	DialTimeout     time.Duration `mapstructure:"dial_timeout" env:"CBC_AUTH_REDIS_DIAL_TIMEOUT" default:"5s"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout" env:"CBC_AUTH_REDIS_READ_TIMEOUT" default:"3s"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout" env:"CBC_AUTH_REDIS_WRITE_TIMEOUT" default:"3s"`
	PoolTimeout     time.Duration `mapstructure:"pool_timeout" env:"CBC_AUTH_REDIS_POOL_TIMEOUT" default:"4s"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time" env:"CBC_AUTH_REDIS_CONN_MAX_IDLE_TIME" default:"5m"`
}

// VaultConfig holds Vault settings.
type VaultConfig struct {
	Address     string        `mapstructure:"address" env:"CBC_AUTH_VAULT_ADDRESS"`
	TokenEnvVar string        `mapstructure:"token_env_var" env:"CBC_AUTH_VAULT_TOKEN_ENV_VAR"`
	Token       string        `mapstructure:"token" env:"CBC_AUTH_VAULT_TOKEN"`
	Timeout     time.Duration `mapstructure:"timeout" env:"CBC_AUTH_VAULT_TIMEOUT" default:"30s"`
	KeyCacheTTL time.Duration `mapstructure:"key_cache_ttl" env:"CBC_AUTH_VAULT_KEY_CACHE_TTL" default:"4h"`
}

// JWTConfig holds JWT settings.
type JWTConfig struct {
	DefaultAlgorithm    string        `mapstructure:"default_algorithm" env:"CBC_AUTH_JWT_DEFAULT_ALGORITHM" default:"RS256"`
	AccessTokenTTL      time.Duration `mapstructure:"access_token_ttl" env:"CBC_AUTH_JWT_ACCESS_TOKEN_TTL" default:"15m"`
	RefreshTokenTTL     time.Duration `mapstructure:"refresh_token_ttl" env:"CBC_AUTH_JWT_REFRESH_TOKEN_TTL" default:"720h"`
	Issuer              string        `mapstructure:"issuer" env:"CBC_AUTH_JWT_ISSUER" default:"cbc-auth-service"`
	SupportedAlgorithms []string      `mapstructure:"supported_algorithms" env:"CBC_AUTH_JWT_SUPPORTED_ALGORITHMS" default:"RS256,RS384,RS512,ES256"`
	ClockSkewTolerance  time.Duration `mapstructure:"clock_skew_tolerance" env:"CBC_AUTH_JWT_CLOCK_SKEW_TOLERANCE" default:"30s"`
}

// RateLimitConfig holds rate limiting settings.
type RateLimitConfig struct {
	Enabled   bool `mapstructure:"enabled" env:"CBC_AUTH_RATELIMIT_ENABLED" default:"true"`
	GlobalRPS int  `mapstructure:"global_rps" env:"CBC_AUTH_RATELIMIT_GLOBAL_RPS" default:"10000"`
	TenantRPS int  `mapstructure:"tenant_rps" env:"CBC_AUTH_RATELIMIT_TENANT_RPS" default:"1000"`
	AgentRPS  int  `mapstructure:"agent_rps" env:"CBC_AUTH_RATELIMIT_AGENT_RPS" default:"10"`
	Burst     int  `mapstructure:"burst" env:"CBC_AUTH_RATELIMIT_BURST" default:"100"`
	RedisKeyPrefix string `mapstructure:"redis_key_prefix" env:"CBC_AUTH_RATELIMIT_REDIS_KEY_PREFIX" default:"ratelimit:"`
}

// IdempotencyConfig holds idempotency settings for replay protection.
type IdempotencyConfig struct {
	Enabled       bool          `mapstructure:"enabled" env:"CBC_AUTH_IDEMPOTENCY_ENABLED" default:"true"`
	RedisCacheTTL time.Duration `mapstructure:"redis_cache_ttl" env:"CBC_AUTH_IDEMPOTENCY_REDIS_CACHE_TTL" default:"24h"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level                 string   `mapstructure:"level" env:"CBC_AUTH_LOG_LEVEL" default:"info"`
	Format                string   `mapstructure:"format" env:"CBC_AUTH_LOG_FORMAT" default:"json"`
	OutputPath            []string `mapstructure:"output_path" env:"CBC_AUTH_LOG_OUTPUT_PATH" default:"stdout"`
	MaxSize               int      `mapstructure:"max_size" env:"CBC_AUTH_LOG_MAX_SIZE" default:"100"`
	MaxBackups            int      `mapstructure:"max_backups" env:"CBC_AUTH_LOG_MAX_BACKUPS" default:"10"`
	MaxAge                int      `mapstructure:"max_age" env:"CBC_AUTH_LOG_MAX_AGE" default:"30"`
	Compress              bool     `mapstructure:"compress" env:"CBC_AUTH_LOG_COMPRESS" default:"true"`
	LocalTime             bool     `mapstructure:"local_time" env:"CBC_AUTH_LOG_LOCAL_TIME" default:"false"`
	SamplingEnabled       bool     `mapstructure:"sampling_enabled" env:"CBC_AUTH_LOG_SAMPLING_ENABLED" default:"false"`
	SamplingInitial       int      `mapstructure:"sampling_initial" env:"CBC_AUTH_LOG_SAMPLING_INITIAL" default:"100"`
	SamplingThereafter    int      `mapstructure:"sampling_thereafter" env:"CBC_AUTH_LOG_SAMPLING_THEREAFTER" default:"100"`
	SamplingTickDuration  int      `mapstructure:"sampling_tick_duration" env:"CBC_AUTH_LOG_SAMPLING_TICK_DURATION" default:"1"`
}

// ObservabilityConfig holds settings for metrics, tracing, and profiling.
type ObservabilityConfig struct {
	Enabled         bool              `mapstructure:"enabled" env:"CBC_AUTH_OBSERVABILITY_ENABLED" default:"true"`
	MetricsEndpoint string            `mapstructure:"metrics_endpoint" env:"CBC_AUTH_OBSERVABILITY_METRICS_ENDPOINT" default:"/metrics"`
	OtelEndpoint    string            `mapstructure:"otel_endpoint" env:"CBC_AUTH_OBSERVABILITY_OTEL_ENDPOINT"`
	ServiceName     string            `mapstructure:"service_name" env:"CBC_AUTH_TRACING_SERVICE_NAME" default:"cbc-auth-service"`
	SamplingRate    float64           `mapstructure:"sampling_rate" env:"CBC_AUTH_TRACING_SAMPLING_RATE" default:"0.1"`
	Environment     string            `mapstructure:"environment" env:"CBC_AUTH_TRACING_ENVIRONMENT" default:"production"`
	Tags            map[string]string `mapstructure:"tags" env:"CBC_AUTH_TRACING_TAGS"`
	PrometheusPort  int               `mapstructure:"prometheus_port" env:"CBC_AUTH_PROMETHEUS_PORT" default:"9090"`
	PprofEnabled    bool              `mapstructure:"pprof_enabled" env:"CBC_AUTH_PPROF_ENABLED" default:"false"`
	PprofPort       int               `mapstructure:"pprof_port" env:"CBC_AUTH_PPROF_PORT" default:"6060"`
}

// Validate checks the entire configuration for correctness.
func (c *Config) Validate() error {
	if err := c.Server.Validate(); err != nil {
		return fmt.Errorf("server config validation failed: %w", err)
	}
	if err := c.Database.Validate(); err != nil {
		return fmt.Errorf("database config validation failed: %w", err)
	}
	if err := c.Redis.Validate(); err != nil {
		return fmt.Errorf("redis config validation failed: %w", err)
	}
	if err := c.Vault.Validate(); err != nil {
		return fmt.Errorf("vault config validation failed: %w", err)
	}
	if err := c.JWT.Validate(); err != nil {
		return fmt.Errorf("jwt config validation failed: %w", err)
	}
	if err := c.RateLimit.Validate(); err != nil {
		return fmt.Errorf("rate limit config validation failed: %w", err)
	}
	if err := c.Idempotency.Validate(); err != nil {
		return fmt.Errorf("idempotency config validation failed: %w", err)
	}
	if err := c.Observability.Validate(); err != nil {
		return fmt.Errorf("observability config validation failed: %w", err)
	}
	if err := c.Log.Validate(); err != nil {
		return fmt.Errorf("log config validation failed: %w", err)
	}
	if err := c.Kafka.Validate(); err != nil {
		return fmt.Errorf("kafka config validation failed: %w", err)
	}
	if err := c.OAuth.Validate(); err != nil {
		return fmt.Errorf("oauth config validation failed: %w", err)
	}
	return nil
}

// Validate OAuthConfig.
func (o *OAuthConfig) Validate() error {
	if o.DeviceAuthExpiresIn <= 0 {
		return fmt.Errorf("device auth expires in must be positive")
	}
	if o.DeviceAuthInterval <= 0 {
		return fmt.Errorf("device auth interval must be positive")
	}
	if o.DeviceAuthExpiresIn <= o.DeviceAuthInterval {
		return fmt.Errorf("device auth expires in must be greater than interval")
	}
	if o.VerificationURI == "" {
		return fmt.Errorf("verification URI is required")
	}
	return nil
}

// Validate KafkaConfig.
func (k *KafkaConfig) Validate() error {
	if len(k.Brokers) == 0 || k.Brokers[0] == "" {
		return fmt.Errorf("kafka brokers are required")
	}
	if k.AuditTopic == "" {
		return fmt.Errorf("kafka audit topic is required")
	}
	if k.BatchSize <= 0 {
		return fmt.Errorf("batch size must be positive")
	}
	return nil
}

// Validate ServerConfig.
func (s *ServerConfig) Validate() error {
	if s.HTTPPort <= 0 || s.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", s.HTTPPort)
	}
	if s.GRPCPort <= 0 || s.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", s.GRPCPort)
	}
	if err := s.TLS.Validate(); err != nil {
		return fmt.Errorf("TLS config validation failed: %w", err)
	}
	return nil
}

// Validate TLSConfig.
func (t *TLSConfig) Validate() error {
	if t.Enabled {
		if t.CertFile == "" {
			return fmt.Errorf("TLS enabled but cert file not specified")
		}
		if t.KeyFile == "" {
			return fmt.Errorf("TLS enabled but key file not specified")
		}
	}
	return nil
}

// Validate DatabaseConfig.
func (d *DatabaseConfig) Validate() error {
	if d.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if d.Port <= 0 || d.Port > 65535 {
		return fmt.Errorf("invalid database port: %d", d.Port)
	}
	if d.User == "" {
		return fmt.Errorf("database user is required")
	}
	if d.Password == "" {
		return fmt.Errorf("database password is required")
	}
	if d.Database == "" {
		return fmt.Errorf("database name is required")
	}
	if d.MaxConns <= 0 {
		return fmt.Errorf("invalid max connections: %d", d.MaxConns)
	}
	if d.MinConns <= 0 {
		return fmt.Errorf("invalid min connections: %d", d.MinConns)
	}
	if d.MinConns > d.MaxConns {
		return fmt.Errorf("min connections (%d) cannot be greater than max connections (%d)", d.MinConns, d.MaxConns)
	}
	return nil
}

// Validate RedisConfig.
func (r *RedisConfig) Validate() error {
	if r.ClusterEnabled {
		if len(r.ClusterAddrs) == 0 {
			return fmt.Errorf("cluster enabled but no cluster addresses specified")
		}
	} else {
		if r.Address == "" {
			return fmt.Errorf("redis address is required")
		}
	}
	if r.PoolSize <= 0 {
		return fmt.Errorf("invalid pool size: %d", r.PoolSize)
	}
	if r.MinIdleConns < 0 {
		return fmt.Errorf("invalid min idle connections: %d", r.MinIdleConns)
	}
	return nil
}

// Validate VaultConfig.
func (v *VaultConfig) Validate() error {
	if v.Address == "" {
		return fmt.Errorf("vault address is required")
	}
	return nil
}

// Validate JWTConfig.
func (j *JWTConfig) Validate() error {
	if j.DefaultAlgorithm == "" {
		return fmt.Errorf("JWT default algorithm is required")
	}
	algorithmSupported := false
	for _, alg := range j.SupportedAlgorithms {
		if alg == j.DefaultAlgorithm {
			algorithmSupported = true
			break
		}
	}
	if !algorithmSupported {
		return fmt.Errorf("default algorithm %s not in supported algorithms list", j.DefaultAlgorithm)
	}
	if j.AccessTokenTTL <= 0 {
		return fmt.Errorf("invalid access token TTL: %v", j.AccessTokenTTL)
	}
	if j.RefreshTokenTTL <= 0 {
		return fmt.Errorf("invalid refresh token TTL: %v", j.RefreshTokenTTL)
	}
	if j.AccessTokenTTL >= j.RefreshTokenTTL {
		return fmt.Errorf("access token TTL (%v) should be less than refresh token TTL (%v)", j.AccessTokenTTL, j.RefreshTokenTTL)
	}
	if j.Issuer == "" {
		return fmt.Errorf("JWT issuer is required")
	}
	return nil
}

// Validate RateLimitConfig.
func (r *RateLimitConfig) Validate() error {
	if r.Enabled {
		if r.GlobalRPS <= 0 {
			return fmt.Errorf("invalid global RPS: %d", r.GlobalRPS)
		}
		if r.TenantRPS <= 0 {
			return fmt.Errorf("invalid tenant RPS: %d", r.TenantRPS)
		}
		if r.AgentRPS <= 0 {
			return fmt.Errorf("invalid agent RPS: %d", r.AgentRPS)
		}
	}
	return nil
}

// Validate IdempotencyConfig.
func (i *IdempotencyConfig) Validate() error {
	if i.Enabled && i.RedisCacheTTL <= 0 {
		return fmt.Errorf("invalid idempotency redis cache TTL: %v", i.RedisCacheTTL)
	}
	return nil
}

// Validate ObservabilityConfig.
func (o *ObservabilityConfig) Validate() error {
	if o.Enabled {
		if o.MetricsEndpoint == "" {
			return fmt.Errorf("metrics endpoint is required")
		}
	}
	return nil
}

// Validate LogConfig.
func (l *LogConfig) Validate() error {
	validLevels := []string{string(constants.LogLevelDebug), string(constants.LogLevelInfo), string(constants.LogLevelWarn), string(constants.LogLevelError), string(constants.LogLevelFatal)}
	levelValid := false
	for _, level := range validLevels {
		if l.Level == level {
			levelValid = true
			break
		}
	}
	if !levelValid {
		return fmt.Errorf("invalid log level: %s (must be one of: debug, info, warn, error, fatal)", l.Level)
	}
	validFormats := []string{"json", "text"}
	formatValid := false
	for _, format := range validFormats {
		if l.Format == format {
			formatValid = true
			break
		}
	}
	if !formatValid {
		return fmt.Errorf("invalid log format: %s (must be json or text)", l.Format)
	}
	if len(l.OutputPath) == 0 {
		return fmt.Errorf("log output path is required")
	}
	return nil
}

// GetDatabaseDSN returns the PostgreSQL connection string.
func (d *DatabaseConfig) GetDatabaseDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Database, d.SSLMode)
}

// GetHTTPAddress returns the HTTP server listen address.
func (s *ServerConfig) GetHTTPAddress() string {
	return fmt.Sprintf("%s:%d", s.HTTPHost, s.HTTPPort)
}

// GetGRPCAddress returns the gRPC server listen address.
func (s *ServerConfig) GetGRPCAddress() string {
	return fmt.Sprintf("%s:%d", s.GRPCHost, s.GRPCPort)
}

// GetRedisAddress returns the Redis address (for standalone mode).
func (r *RedisConfig) GetRedisAddress() string {
	if r.ClusterEnabled {
		return ""
	}
	return r.Address
}

