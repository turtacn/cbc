// Package config 提供配置加载和管理功能
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Loader 配置加载器接口
type Loader interface {
	Load() (*Config, error)
	Reload() error
	Watch(callback func(*Config)) error
	GetConfig() *Config
}

// ConfigLoader 配置加载器实现
type ConfigLoader struct {
	viper      *viper.Viper
	config     *Config
	mu         sync.RWMutex
	logger     *zap.Logger
	callbacks  []func(*Config)
	configFile string
	watching   bool
}

// LoaderOption 加载器选项
type LoaderOption func(*ConfigLoader)

// WithLogger 设置日志器
func WithLogger(logger *zap.Logger) LoaderOption {
	return func(l *ConfigLoader) {
		l.logger = logger
	}
}

// WithConfigFile 设置配置文件路径
func WithConfigFile(path string) LoaderOption {
	return func(l *ConfigLoader) {
		l.configFile = path
	}
}

// NewLoader 创建配置加载器
func NewLoader(opts ...LoaderOption) Loader {
	v := viper.New()

	loader := &ConfigLoader{
		viper:     v,
		callbacks: make([]func(*Config), 0),
		logger:    zap.NewNop(), // 默认无日志
	}

	// 应用选项
	for _, opt := range opts {
		opt(loader)
	}

	return loader
}

// Load 加载配置
func (l *ConfigLoader) Load() (*Config, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// 配置文件路径优先级：
	// 1. 通过 WithConfigFile 指定的路径
	// 2. 环境变量 CBC_AUTH_CONFIG_FILE
	// 3. 默认路径列表
	if l.configFile == "" {
		l.configFile = os.Getenv("CBC_AUTH_CONFIG_FILE")
	}

	if l.configFile != "" {
		// 使用指定的配置文件
		l.viper.SetConfigFile(l.configFile)
		if l.logger != nil {
			l.logger.Info("Using config file", zap.String("path", l.configFile))
		}
	} else {
		// 使用默认搜索路径
		l.viper.SetConfigName("config")
		l.viper.SetConfigType("yaml")
		l.viper.AddConfigPath("./configs")
		l.viper.AddConfigPath(".")
		l.viper.AddConfigPath("/etc/cbc-auth")
		l.viper.AddConfigPath("$HOME/.cbc-auth")
	}

	// 设置环境变量前缀
	l.viper.SetEnvPrefix("CBC_AUTH")
	l.viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	l.viper.AutomaticEnv()

	// 设置默认值
	l.setDefaults()

	// 读取配置文件（如果存在）
	if err := l.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// 配置文件不存在，使用默认值和环境变量
			if l.logger != nil {
				l.logger.Warn("Config file not found, using defaults and environment variables")
			}
		} else {
			// 配置文件存在但读取失败
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	} else {
		if l.logger != nil {
			l.logger.Info("Config file loaded", zap.String("file", l.viper.ConfigFileUsed()))
		}
	}

	// 解析配置到结构体
	cfg := &Config{}
	if err := l.viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// 验证配置
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	l.config = cfg

	if l.logger != nil {
		l.logger.Info("Configuration loaded successfully",
			zap.String("http_address", cfg.Server.GetHTTPAddress()),
			zap.String("grpc_address", cfg.Server.GetGRPCAddress()),
			zap.String("log_level", cfg.Log.Level),
		)
	}

	return cfg, nil
}

// Reload 重新加载配置
func (l *ConfigLoader) Reload() error {
	if l.logger != nil {
		l.logger.Info("Reloading configuration...")
	}

	cfg, err := l.Load()
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	// 触发回调
	l.mu.RLock()
	callbacks := l.callbacks
	l.mu.RUnlock()

	for _, callback := range callbacks {
		go callback(cfg)
	}

	if l.logger != nil {
		l.logger.Info("Configuration reloaded successfully")
	}

	return nil
}

// Watch 监听配置文件变化
func (l *ConfigLoader) Watch(callback func(*Config)) error {
	l.mu.Lock()
	if l.watching {
		l.mu.Unlock()
		return fmt.Errorf("already watching config file")
	}
	l.watching = true
	l.callbacks = append(l.callbacks, callback)
	l.mu.Unlock()

	// 使用 viper 的 WatchConfig
	l.viper.WatchConfig()
	l.viper.OnConfigChange(func(e fsnotify.Event) {
		if l.logger != nil {
			l.logger.Info("Config file changed", zap.String("file", e.Name))
		}

		// 延迟重新加载，避免文件正在写入时读取
		time.Sleep(100 * time.Millisecond)

		if err := l.Reload(); err != nil {
			if l.logger != nil {
				l.logger.Error("Failed to reload config after file change", zap.Error(err))
			}
		}
	})

	if l.logger != nil {
		l.logger.Info("Started watching config file for changes")
	}

	return nil
}

// GetConfig 获取当前配置
func (l *ConfigLoader) GetConfig() *Config {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

// setDefaults 设置默认配置值
func (l *ConfigLoader) setDefaults() {
	// Server 默认值
	l.viper.SetDefault("server.http_host", "0.0.0.0")
	l.viper.SetDefault("server.http_port", 8080)
	l.viper.SetDefault("server.http_read_timeout", "30s")
	l.viper.SetDefault("server.http_write_timeout", "30s")
	l.viper.SetDefault("server.http_idle_timeout", "120s")
	l.viper.SetDefault("server.grpc_host", "0.0.0.0")
	l.viper.SetDefault("server.grpc_port", 50051)
	l.viper.SetDefault("server.grpc_max_connection_idle", "5m")
	l.viper.SetDefault("server.grpc_max_connection_age", "30m")
	l.viper.SetDefault("server.grpc_keepalive_time", "2h")
	l.viper.SetDefault("server.grpc_keepalive_timeout", "20s")
	l.viper.SetDefault("server.tls_enabled", true)
	l.viper.SetDefault("server.shutdown_timeout", "30s")

	// Database 默认值
	l.viper.SetDefault("database.host", "localhost")
	l.viper.SetDefault("database.port", 5432)
	l.viper.SetDefault("database.user", "cbc_auth")
	l.viper.SetDefault("database.database", "cbc_auth_db")
	l.viper.SetDefault("database.ssl_mode", "require")
	l.viper.SetDefault("database.max_conns", 100)
	l.viper.SetDefault("database.min_conns", 10)
	l.viper.SetDefault("database.max_conn_lifetime", "1h")
	l.viper.SetDefault("database.max_conn_idle_time", "30m")
	l.viper.SetDefault("database.connect_timeout", "10s")

	// Redis 默认值
	l.viper.SetDefault("redis.address", "localhost:6379")
	l.viper.SetDefault("redis.db", 0)
	l.viper.SetDefault("redis.cluster_enabled", false)
	l.viper.SetDefault("redis.pool_size", 100)
	l.viper.SetDefault("redis.min_idle_conns", 10)
	l.viper.SetDefault("redis.max_retries", 3)
	l.viper.SetDefault("redis.dial_timeout", "5s")
	l.viper.SetDefault("redis.read_timeout", "3s")
	l.viper.SetDefault("redis.write_timeout", "3s")
	l.viper.SetDefault("redis.pool_timeout", "4s")
	l.viper.SetDefault("redis.conn_max_idle_time", "5m")

	// Vault 默认值
	l.viper.SetDefault("vault.address", "https://vault.cbc-platform.svc.cluster.local:8200")
	l.viper.SetDefault("vault.mount_path", "secret/cbc")
	l.viper.SetDefault("vault.key_cache_ttl", "4h")
	l.viper.SetDefault("vault.key_refresh_interval", "1h")
	l.viper.SetDefault("vault.key_rotation_check_time", "24h")
	l.viper.SetDefault("vault.max_retries", 3)
	l.viper.SetDefault("vault.timeout", "30s")
	l.viper.SetDefault("vault.tls_skip_verify", false)

	// JWT 默认值
	l.viper.SetDefault("jwt.default_algorithm", "RS256")
	l.viper.SetDefault("jwt.access_token_ttl", "15m")
	l.viper.SetDefault("jwt.refresh_token_ttl", "720h") // 30天
	l.viper.SetDefault("jwt.issuer", "cbc-auth-service")
	l.viper.SetDefault("jwt.supported_algorithms", []string{"RS256", "RS384", "RS512", "ES256"})
	l.viper.SetDefault("jwt.clock_skew_tolerance", "30s")

	// RateLimit 默认值
	l.viper.SetDefault("rate_limit.global_enabled", true)
	l.viper.SetDefault("rate_limit.global_rpm", 1000000)
	l.viper.SetDefault("rate_limit.global_burst", 10000)
	l.viper.SetDefault("rate_limit.tenant_enabled", true)
	l.viper.SetDefault("rate_limit.tenant_rpm", 100000)
	l.viper.SetDefault("rate_limit.tenant_burst", 1000)
	l.viper.SetDefault("rate_limit.agent_enabled", true)
	l.viper.SetDefault("rate_limit.agent_rpm", 600)
	l.viper.SetDefault("rate_limit.agent_burst", 20)
	l.viper.SetDefault("rate_limit.window_size", "1m")
	l.viper.SetDefault("rate_limit.redis_key_prefix", "ratelimit:")

	// Log 默认值
	l.viper.SetDefault("log.level", "info")
	l.viper.SetDefault("log.format", "json")
	l.viper.SetDefault("log.output_path", []string{"stdout"})
	l.viper.SetDefault("log.max_size", 100)
	l.viper.SetDefault("log.max_backups", 10)
	l.viper.SetDefault("log.max_age", 30)
	l.viper.SetDefault("log.compress", true)
	l.viper.SetDefault("log.local_time", false)
	l.viper.SetDefault("log.sampling_enabled", false)
	l.viper.SetDefault("log.sampling_initial", 100)
	l.viper.SetDefault("log.sampling_thereafter", 100)
	l.viper.SetDefault("log.sampling_tick_duration", 1)

	// Tracing 默认值
	l.viper.SetDefault("tracing.enabled", true)
	l.viper.SetDefault("tracing.service_name", "cbc-auth-service")
	l.viper.SetDefault("tracing.jaeger_endpoint", "http://jaeger:14268/api/traces")
	l.viper.SetDefault("tracing.sampling_rate", 0.1)
	l.viper.SetDefault("tracing.agent_host", "localhost")
	l.viper.SetDefault("tracing.agent_port", "6831")
	l.viper.SetDefault("tracing.environment", "production")

	// Monitoring 默认值
	l.viper.SetDefault("monitoring.prometheus_enabled", true)
	l.viper.SetDefault("monitoring.prometheus_port", 9090)
	l.viper.SetDefault("monitoring.prometheus_path", "/metrics")
	l.viper.SetDefault("monitoring.health_check_path", "/health")
	l.viper.SetDefault("monitoring.readiness_path", "/ready")
	l.viper.SetDefault("monitoring.liveness_path", "/live")
	l.viper.SetDefault("monitoring.pprof_enabled", false)
	l.viper.SetDefault("monitoring.pprof_port", 6060)
}

// LoadFromFile 从指定文件加载配置（辅助函数）
func LoadFromFile(path string, logger *zap.Logger) (*Config, error) {
	loader := NewLoader(
		WithConfigFile(path),
		WithLogger(logger),
	)
	return loader.Load()
}

// LoadFromEnv 仅从环境变量加载配置（辅助函数）
func LoadFromEnv(logger *zap.Logger) (*Config, error) {
	loader := NewLoader(WithLogger(logger))
	return loader.Load()
}

// MustLoad 加载配置，失败时 panic（辅助函数）
func MustLoad(opts ...LoaderOption) *Config {
	loader := NewLoader(opts...)
	cfg, err := loader.Load()
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}
	return cfg
}

// WriteDefaultConfig 写入默认配置文件到指定路径
func WriteDefaultConfig(path string) error {
	// 确保目录存在
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// 创建默认配置
	defaultConfig := `# CBC Auth Service Configuration

server:
  http_host: 0.0.0.0
  http_port: 8080
  http_read_timeout: 30s
  http_write_timeout: 30s
  http_idle_timeout: 120s
  grpc_host: 0.0.0.0
  grpc_port: 50051
  tls_enabled: true
  tls_cert_file: /etc/cbc-auth/tls/tls.crt
  tls_key_file: /etc/cbc-auth/tls/tls.key
  shutdown_timeout: 30s

database:
  host: localhost
  port: 5432
  user: cbc_auth
  password: changeme
  database: cbc_auth_db
  ssl_mode: require
  max_conns: 100
  min_conns: 10
  max_conn_lifetime: 1h
  max_conn_idle_time: 30m
  connect_timeout: 10s

redis:
  address: localhost:6379
  password: ""
  db: 0
  cluster_enabled: false
  pool_size: 100
  min_idle_conns: 10
  max_retries: 3
  dial_timeout: 5s
  read_timeout: 3s
  write_timeout: 3s

vault:
  address: https://vault.cbc-platform.svc.cluster.local:8200
  token: ""
  role_id: ""
  secret_id: ""
  mount_path: secret/cbc
  key_cache_ttl: 4h
  key_refresh_interval: 1h
  max_retries: 3
  timeout: 30s
  tls_skip_verify: false

jwt:
  default_algorithm: RS256
  access_token_ttl: 15m
  refresh_token_ttl: 720h
  issuer: cbc-auth-service
  supported_algorithms:
    - RS256
    - RS384
    - RS512
    - ES256
  clock_skew_tolerance: 30s

rate_limit:
  global_enabled: true
  global_rpm: 1000000
  global_burst: 10000
  tenant_enabled: true
  tenant_rpm: 100000
  tenant_burst: 1000
  agent_enabled: true
  agent_rpm: 600
  agent_burst: 20
  window_size: 1m
  redis_key_prefix: "ratelimit:"

log:
  level: info
  format: json
  output_path:
    - stdout
  max_size: 100
  max_backups: 10
  max_age: 30
  compress: true
  local_time: false

tracing:
  enabled: true
  service_name: cbc-auth-service
  jaeger_endpoint: http://jaeger:14268/api/traces
  sampling_rate: 0.1
  agent_host: localhost
  agent_port: "6831"
  environment: production

monitoring:
  prometheus_enabled: true
  prometheus_port: 9090
  prometheus_path: /metrics
  health_check_path: /health
  readiness_path: /ready
  liveness_path: /live
  pprof_enabled: false
  pprof_port: 6060
`

	// 写入文件
	if err := os.WriteFile(path, []byte(defaultConfig), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

//Personal.AI order the ending
