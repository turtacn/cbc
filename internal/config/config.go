// Package config 定义服务配置结构
package config

import (
	"fmt"
	"time"

	"github.com/turtacn/cbc/pkg/constants"
)

// Config 服务总配置结构
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Database   DatabaseConfig   `mapstructure:"database"`
	Redis      RedisConfig      `mapstructure:"redis"`
	Vault      VaultConfig      `mapstructure:"vault"`
	JWT        JWTConfig        `mapstructure:"jwt"`
	RateLimit  RateLimitConfig  `mapstructure:"rate_limit"`
	Log        LogConfig        `mapstructure:"log"`
	Tracing    TracingConfig    `mapstructure:"tracing"`
	Monitoring MonitoringConfig `mapstructure:"monitoring"`
}

// ServerConfig HTTP/gRPC 服务配置
type ServerConfig struct {
	// HTTP 服务配置
	HTTPHost         string        `mapstructure:"http_host" env:"CBC_AUTH_HTTP_HOST" default:"0.0.0.0"`
	HTTPPort         int           `mapstructure:"http_port" env:"CBC_AUTH_HTTP_PORT" default:"8080"`
	HTTPReadTimeout  time.Duration `mapstructure:"http_read_timeout" env:"CBC_AUTH_HTTP_READ_TIMEOUT" default:"30s"`
	HTTPWriteTimeout time.Duration `mapstructure:"http_write_timeout" env:"CBC_AUTH_HTTP_WRITE_TIMEOUT" default:"30s"`
	HTTPIdleTimeout  time.Duration `mapstructure:"http_idle_timeout" env:"CBC_AUTH_HTTP_IDLE_TIMEOUT" default:"120s"`

	// gRPC 服务配置
	GRPCHost              string        `mapstructure:"grpc_host" env:"CBC_AUTH_GRPC_HOST" default:"0.0.0.0"`
	GRPCPort              int           `mapstructure:"grpc_port" env:"CBC_AUTH_GRPC_PORT" default:"50051"`
	GRPCMaxConnectionIdle time.Duration `mapstructure:"grpc_max_connection_idle" env:"CBC_AUTH_GRPC_MAX_CONNECTION_IDLE" default:"5m"`
	GRPCMaxConnectionAge  time.Duration `mapstructure:"grpc_max_connection_age" env:"CBC_AUTH_GRPC_MAX_CONNECTION_AGE" default:"30m"`
	GRPCKeepAliveTime     time.Duration `mapstructure:"grpc_keepalive_time" env:"CBC_AUTH_GRPC_KEEPALIVE_TIME" default:"2h"`
	GRPCKeepAliveTimeout  time.Duration `mapstructure:"grpc_keepalive_timeout" env:"CBC_AUTH_GRPC_KEEPALIVE_TIMEOUT" default:"20s"`

	// TLS 配置
	TLSEnabled  bool   `mapstructure:"tls_enabled" env:"CBC_AUTH_TLS_ENABLED" default:"true"`
	TLSCertFile string `mapstructure:"tls_cert_file" env:"CBC_AUTH_TLS_CERT_FILE"`
	TLSKeyFile  string `mapstructure:"tls_key_file" env:"CBC_AUTH_TLS_KEY_FILE"`

	// 优雅关闭超时
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout" env:"CBC_AUTH_SHUTDOWN_TIMEOUT" default:"30s"`
}

// DatabaseConfig PostgreSQL 配置
type DatabaseConfig struct {
	DSN             string        `mapstructure:"dsn" env:"PG_DSN"`
	Host            string        `mapstructure:"host" env:"CBC_AUTH_DB_HOST" default:"localhost"`
	Port            int           `mapstructure:"port" env:"CBC_AUTH_DB_PORT" default:"5432"`
	User            string        `mapstructure:"user" env:"CBC_AUTH_DB_USER" default:"cbc_auth"`
	Password        string        `mapstructure:"password" env:"CBC_AUTH_DB_PASSWORD"`
	Database        string        `mapstructure:"database" env:"CBC_AUTH_DB_NAME" default:"cbc_auth_db"`
	SSLMode         string        `mapstructure:"ssl_mode" env:"CBC_AUTH_DB_SSL_MODE" default:"require"`
	MaxConns          int32         `mapstructure:"max_conns" env:"CBC_AUTH_DB_MAX_CONNS" default:"100"`
	MinConns          int32         `mapstructure:"min_conns" env:"CBC_AUTH_DB_MIN_CONNS" default:"10"`
	MaxConnLifetime   time.Duration `mapstructure:"max_conn_lifetime" env:"CBC_AUTH_DB_MAX_CONN_LIFETIME" default:"1h"`
	MaxConnIdleTime   time.Duration `mapstructure:"max_conn_idle_time" env:"CBC_AUTH_DB_MAX_CONN_IDLE_TIME" default:"30m"`
	HealthCheckPeriod time.Duration `mapstructure:"health_check_period" env:"CBC_AUTH_DB_HEALTH_CHECK_PERIOD" default:"5m"`
	ConnTimeout       time.Duration `mapstructure:"conn_timeout" env:"CBC_AUTH_DB_CONN_TIMEOUT" default:"10s"`
}

// RedisConfig Redis 配置
type RedisConfig struct {
	Addr string `mapstructure:"addr" env:"REDIS_ADDR"`
	// 单节点配置
	Address  string `mapstructure:"address" env:"CBC_AUTH_REDIS_ADDRESS" default:"localhost:6379"`
	Password string `mapstructure:"password" env:"CBC_AUTH_REDIS_PASSWORD"`
	DB       int    `mapstructure:"db" env:"REDIS_DB"`

	// 集群配置
	ClusterEnabled bool     `mapstructure:"cluster_enabled" env:"CBC_AUTH_REDIS_CLUSTER_ENABLED" default:"false"`
	ClusterAddrs   []string `mapstructure:"cluster_addrs" env:"CBC_AUTH_REDIS_CLUSTER_ADDRS"`

	// 连接池配置
	PoolSize        int           `mapstructure:"pool_size" env:"CBC_AUTH_REDIS_POOL_SIZE" default:"100"`
	MinIdleConns    int           `mapstructure:"min_idle_conns" env:"CBC_AUTH_REDIS_MIN_IDLE_CONNS" default:"10"`
	MaxRetries      int           `mapstructure:"max_retries" env:"CBC_AUTH_REDIS_MAX_RETRIES" default:"3"`
	DialTimeout     time.Duration `mapstructure:"dial_timeout" env:"CBC_AUTH_REDIS_DIAL_TIMEOUT" default:"5s"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout" env:"CBC_AUTH_REDIS_READ_TIMEOUT" default:"3s"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout" env:"CBC_AUTH_REDIS_WRITE_TIMEOUT" default:"3s"`
	PoolTimeout     time.Duration `mapstructure:"pool_timeout" env:"CBC_AUTH_REDIS_POOL_TIMEOUT" default:"4s"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time" env:"CBC_AUTH_REDIS_CONN_MAX_IDLE_TIME" default:"5m"`
}

// VaultConfig Vault 配置
type VaultConfig struct {
	Address   string `mapstructure:"address" env:"CBC_AUTH_VAULT_ADDRESS" default:"https://vault.cbc-platform.svc.cluster.local:8200"`
	Token     string `mapstructure:"token" env:"CBC_AUTH_VAULT_TOKEN"`
	RoleID    string `mapstructure:"role_id" env:"CBC_AUTH_VAULT_ROLE_ID"`
	SecretID  string `mapstructure:"secret_id" env:"CBC_AUTH_VAULT_SECRET_ID"`
	MountPath string `mapstructure:"mount_path" env:"CBC_AUTH_VAULT_MOUNT_PATH" default:"secret/cbc"`

	// 密钥缓存配置
	KeyCacheTTL          time.Duration `mapstructure:"key_cache_ttl" env:"CBC_AUTH_VAULT_KEY_CACHE_TTL" default:"4h"`
	KeyRefreshInterval   time.Duration `mapstructure:"key_refresh_interval" env:"CBC_AUTH_VAULT_KEY_REFRESH_INTERVAL" default:"1h"`
	KeyRotationCheckTime time.Duration `mapstructure:"key_rotation_check_time" env:"CBC_AUTH_VAULT_KEY_ROTATION_CHECK_TIME" default:"24h"`

	// 连接配置
	MaxRetries    int           `mapstructure:"max_retries" env:"CBC_AUTH_VAULT_MAX_RETRIES" default:"3"`
	Timeout       time.Duration `mapstructure:"timeout" env:"CBC_AUTH_VAULT_TIMEOUT" default:"30s"`
	TLSSkipVerify bool          `mapstructure:"tls_skip_verify" env:"CBC_AUTH_VAULT_TLS_SKIP_VERIFY" default:"false"`
}

// JWTConfig JWT 配置
type JWTConfig struct {
	// 默认算法
	DefaultAlgorithm string `mapstructure:"default_algorithm" env:"CBC_AUTH_JWT_DEFAULT_ALGORITHM" default:"RS256"`

	// Token TTL 配置
	AccessTokenTTL  time.Duration `mapstructure:"access_token_ttl" env:"CBC_AUTH_JWT_ACCESS_TOKEN_TTL" default:"15m"`
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl" env:"CBC_AUTH_JWT_REFRESH_TOKEN_TTL" default:"720h"` // 30天

	// Token 颁发者
	Issuer string `mapstructure:"issuer" env:"CBC_AUTH_JWT_ISSUER" default:"cbc-auth-service"`

	// 支持的算法列表
	SupportedAlgorithms []string `mapstructure:"supported_algorithms" env:"CBC_AUTH_JWT_SUPPORTED_ALGORITHMS" default:"RS256,RS384,RS512,ES256"`

	// 时钟偏移容忍度（防止时钟不同步导致的验证失败）
	ClockSkewTolerance time.Duration `mapstructure:"clock_skew_tolerance" env:"CBC_AUTH_JWT_CLOCK_SKEW_TOLERANCE" default:"30s"`
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	// 全局限流
	GlobalEnabled bool `mapstructure:"global_enabled" env:"CBC_AUTH_RATELIMIT_GLOBAL_ENABLED" default:"true"`
	GlobalRPM     int  `mapstructure:"global_rpm" env:"CBC_AUTH_RATELIMIT_GLOBAL_RPM" default:"1000000"` // 100万 RPM
	GlobalBurst   int  `mapstructure:"global_burst" env:"CBC_AUTH_RATELIMIT_GLOBAL_BURST" default:"10000"`

	// 租户级别限流
	TenantEnabled bool `mapstructure:"tenant_enabled" env:"CBC_AUTH_RATELIMIT_TENANT_ENABLED" default:"true"`
	TenantRPM     int  `mapstructure:"tenant_rpm" env:"CBC_AUTH_RATELIMIT_TENANT_RPM" default:"100000"` // 10万 RPM
	TenantBurst   int  `mapstructure:"tenant_burst" env:"CBC_AUTH_RATELIMIT_TENANT_BURST" default:"1000"`

	// Agent 级别限流
	AgentEnabled bool `mapstructure:"agent_enabled" env:"CBC_AUTH_RATELIMIT_AGENT_ENABLED" default:"true"`
	AgentRPM     int  `mapstructure:"agent_rpm" env:"CBC_AUTH_RATELIMIT_AGENT_RPM" default:"600"` // 10 RPM
	AgentBurst   int  `mapstructure:"agent_burst" env:"CBC_AUTH_RATELIMIT_AGENT_BURST" default:"20"`

	// 限流窗口大小
	WindowSize time.Duration `mapstructure:"window_size" env:"CBC_AUTH_RATELIMIT_WINDOW_SIZE" default:"1m"`

	// Redis Key 前缀
	RedisKeyPrefix string `mapstructure:"redis_key_prefix" env:"CBC_AUTH_RATELIMIT_REDIS_KEY_PREFIX" default:"ratelimit:"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level      string   `mapstructure:"level" env:"CBC_AUTH_LOG_LEVEL" default:"info"`
	Format     string   `mapstructure:"format" env:"CBC_AUTH_LOG_FORMAT" default:"json"` // json or text
	OutputPath []string `mapstructure:"output_path" env:"CBC_AUTH_LOG_OUTPUT_PATH" default:"stdout"`

	// 日志文件轮转配置（如果输出到文件）
	MaxSize    int  `mapstructure:"max_size" env:"CBC_AUTH_LOG_MAX_SIZE" default:"100"`       // MB
	MaxBackups int  `mapstructure:"max_backups" env:"CBC_AUTH_LOG_MAX_BACKUPS" default:"10"`  // 保留文件数
	MaxAge     int  `mapstructure:"max_age" env:"CBC_AUTH_LOG_MAX_AGE" default:"30"`          // 天
	Compress   bool `mapstructure:"compress" env:"CBC_AUTH_LOG_COMPRESS" default:"true"`      // 是否压缩
	LocalTime  bool `mapstructure:"local_time" env:"CBC_AUTH_LOG_LOCAL_TIME" default:"false"` // 使用本地时间

	// 采样配置（高并发下减少日志量）
	SamplingEnabled       bool `mapstructure:"sampling_enabled" env:"CBC_AUTH_LOG_SAMPLING_ENABLED" default:"false"`
	SamplingInitial       int  `mapstructure:"sampling_initial" env:"CBC_AUTH_LOG_SAMPLING_INITIAL" default:"100"`
	SamplingThereafter    int  `mapstructure:"sampling_thereafter" env:"CBC_AUTH_LOG_SAMPLING_THEREAFTER" default:"100"`
	SamplingTickDuration  int  `mapstructure:"sampling_tick_duration" env:"CBC_AUTH_LOG_SAMPLING_TICK_DURATION" default:"1"` // 秒
}

// TracingConfig 链路追踪配置
type TracingConfig struct {
	Enabled         bool    `mapstructure:"enabled" env:"CBC_AUTH_TRACING_ENABLED" default:"true"`
	ServiceName     string  `mapstructure:"service_name" env:"CBC_AUTH_TRACING_SERVICE_NAME" default:"cbc-auth-service"`
	JaegerEndpoint  string  `mapstructure:"jaeger_endpoint" env:"CBC_AUTH_TRACING_JAEGER_ENDPOINT" default:"http://jaeger:14268/api/traces"`
	SamplingRate    float64 `mapstructure:"sampling_rate" env:"CBC_AUTH_TRACING_SAMPLING_RATE" default:"0.1"` // 10% 采样率
	AgentHost       string  `mapstructure:"agent_host" env:"CBC_AUTH_TRACING_AGENT_HOST" default:"localhost"`
	AgentPort       string  `mapstructure:"agent_port" env:"CBC_AUTH_TRACING_AGENT_PORT" default:"6831"`
	CollectorURL    string  `mapstructure:"collector_url" env:"CBC_AUTH_TRACING_COLLECTOR_URL"`

	// 追踪标签
	Environment string            `mapstructure:"environment" env:"CBC_AUTH_TRACING_ENVIRONMENT" default:"production"`
	Tags        map[string]string `mapstructure:"tags" env:"CBC_AUTH_TRACING_TAGS"`
}

// MonitoringConfig 监控配置
type MonitoringConfig struct {
	// Prometheus 配置
	PrometheusEnabled bool   `mapstructure:"prometheus_enabled" env:"CBC_AUTH_PROMETHEUS_ENABLED" default:"true"`
	PrometheusPort    int    `mapstructure:"prometheus_port" env:"CBC_AUTH_PROMETHEUS_PORT" default:"9090"`
	PrometheusPath    string `mapstructure:"prometheus_path" env:"CBC_AUTH_PROMETHEUS_PATH" default:"/metrics"`

	// 健康检查配置
	HealthCheckPath string `mapstructure:"health_check_path" env:"CBC_AUTH_HEALTH_CHECK_PATH" default:"/health"`
	ReadinessPath   string `mapstructure:"readiness_path" env:"CBC_AUTH_READINESS_PATH" default:"/ready"`
	LivenessPath    string `mapstructure:"liveness_path" env:"CBC_AUTH_LIVENESS_PATH" default:"/live"`

	// 性能分析配置
	PprofEnabled bool `mapstructure:"pprof_enabled" env:"CBC_AUTH_PPROF_ENABLED" default:"false"`
	PprofPort    int  `mapstructure:"pprof_port" env:"CBC_AUTH_PPROF_PORT" default:"6060"`
}

// Validate 验证配置的合法性
func (c *Config) Validate() error {
	// 验证服务器配置
	if err := c.Server.Validate(); err != nil {
		return fmt.Errorf("server config validation failed: %w", err)
	}

	// 验证数据库配置
	if err := c.Database.Validate(); err != nil {
		return fmt.Errorf("database config validation failed: %w", err)
	}

	// 验证 Redis 配置
	if err := c.Redis.Validate(); err != nil {
		return fmt.Errorf("redis config validation failed: %w", err)
	}

	// 验证 Vault 配置
	if err := c.Vault.Validate(); err != nil {
		return fmt.Errorf("vault config validation failed: %w", err)
	}

	// 验证 JWT 配置
	if err := c.JWT.Validate(); err != nil {
		return fmt.Errorf("jwt config validation failed: %w", err)
	}

	// 验证限流配置
	if err := c.RateLimit.Validate(); err != nil {
		return fmt.Errorf("rate limit config validation failed: %w", err)
	}

	// 验证日志配置
	if err := c.Log.Validate(); err != nil {
		return fmt.Errorf("log config validation failed: %w", err)
	}

	return nil
}

// Validate ServerConfig
func (s *ServerConfig) Validate() error {
	if s.HTTPPort <= 0 || s.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", s.HTTPPort)
	}
	if s.GRPCPort <= 0 || s.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", s.GRPCPort)
	}
	if s.TLSEnabled {
		if s.TLSCertFile == "" {
			return fmt.Errorf("TLS enabled but cert file not specified")
		}
		if s.TLSKeyFile == "" {
			return fmt.Errorf("TLS enabled but key file not specified")
		}
	}
	return nil
}

// Validate DatabaseConfig
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

// Validate RedisConfig
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

// Validate VaultConfig
func (v *VaultConfig) Validate() error {
	if v.Address == "" {
		return fmt.Errorf("vault address is required")
	}
	// Token 或 RoleID/SecretID 至少需要一种认证方式
	if v.Token == "" && (v.RoleID == "" || v.SecretID == "") {
		return fmt.Errorf("vault authentication required: provide either token or roleID+secretID")
	}
	if v.MountPath == "" {
		return fmt.Errorf("vault mount path is required")
	}
	return nil
}

// Validate JWTConfig
func (j *JWTConfig) Validate() error {
	if j.DefaultAlgorithm == "" {
		return fmt.Errorf("JWT default algorithm is required")
	}
	// 验证算法是否在支持列表中
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

// Validate RateLimitConfig
func (r *RateLimitConfig) Validate() error {
	if r.GlobalEnabled && r.GlobalRPM <= 0 {
		return fmt.Errorf("invalid global RPM: %d", r.GlobalRPM)
	}
	if r.TenantEnabled && r.TenantRPM <= 0 {
		return fmt.Errorf("invalid tenant RPM: %d", r.TenantRPM)
	}
	if r.AgentEnabled && r.AgentRPM <= 0 {
		return fmt.Errorf("invalid agent RPM: %d", r.AgentRPM)
	}
	if r.WindowSize <= 0 {
		return fmt.Errorf("invalid window size: %v", r.WindowSize)
	}
	return nil
}

// Validate LogConfig
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

// GetDatabaseDSN 返回 PostgreSQL 连接字符串
func (d *DatabaseConfig) GetDatabaseDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Database, d.SSLMode)
}

// GetHTTPAddress 返回 HTTP 服务监听地址
func (s *ServerConfig) GetHTTPAddress() string {
	return fmt.Sprintf("%s:%d", s.HTTPHost, s.HTTPPort)
}

// GetGRPCAddress 返回 gRPC 服务监听地址
func (s *ServerConfig) GetGRPCAddress() string {
	return fmt.Sprintf("%s:%d", s.GRPCHost, s.GRPCPort)
}

// GetRedisAddress 返回 Redis 地址（用于单节点模式）
func (r *RedisConfig) GetRedisAddress() string {
	if r.ClusterEnabled {
		return "" // 集群模式使用 ClusterAddrs
	}
	return r.Address
}

// GetVaultPath 返回完整的 Vault 密钥路径
func (v *VaultConfig) GetVaultPath(subPath string) string {
	return fmt.Sprintf("%s/%s", v.MountPath, subPath)
}

//Personal.AI order the ending
