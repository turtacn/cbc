package config

import (
	"fmt"
)

// Config holds the application's configuration.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Redis     RedisConfig     `mapstructure:"redis"`
	Vault     VaultConfig     `mapstructure:"vault"`
	JWT       JWTConfig       `mapstructure:"jwt"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	Log       LogConfig       `mapstructure:"log"`
	Tracing   TracingConfig   `mapstructure:"tracing"`
}

type ServerConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	GRPCPort     int    `mapstructure:"grpc_port"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
}

type DatabaseConfig struct {
	Host            string `mapstructure:"host"`
	Port            int    `mapstructure:"port"`
	User            string `mapstructure:"user"`
	Password        string `mapstructure:"password"`
	Database        string `mapstructure:"database"`
	SSLMode         string `mapstructure:"ssl_mode"`
	MaxConns        int    `mapstructure:"max_conns"`
	MinConns        int    `mapstructure:"min_conns"`
	MaxConnLifetime int    `mapstructure:"max_conn_lifetime"`  // in minutes
	MaxConnIdleTime int    `mapstructure:"max_conn_idle_time"` // in minutes
}

func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode)
}

type RedisConfig struct {
	Addresses    []string `mapstructure:"addresses"`
	Password     string   `mapstructure:"password"`
	DB           int      `mapstructure:"db"`
	PoolSize     int      `mapstructure:"pool_size"`
	MinIdleConns int      `mapstructure:"min_idle_conns"`
}

type VaultConfig struct {
	Address   string `mapstructure:"address"`
	Token     string `mapstructure:"token"`
	MountPath string `mapstructure:"mount_path"`
}

type JWTConfig struct {
	DefaultAlgorithm string `mapstructure:"default_algorithm"`
	AccessTokenTTL   int    `mapstructure:"access_token_ttl"`  // in seconds
	RefreshTokenTTL  int    `mapstructure:"refresh_token_ttl"` // in seconds
}

type RateLimitConfig struct {
	DefaultRPM int `mapstructure:"default_rpm"`
	BurstSize  int `mapstructure:"burst_size"`
}

type LogConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	OutputPath string `mapstructure:"output_path"`
}

type TracingConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	JaegerEndpoint string `mapstructure:"jaeger_endpoint"`
	ServiceName    string `mapstructure:"service_name"`
}

// Validate checks for essential configuration values.
func (c *Config) Validate() error {
	// Add validation logic here
	return nil
}

//Personal.AI order the ending
