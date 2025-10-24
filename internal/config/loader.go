package config

import (
	"strings"

	"github.com/spf13/viper"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// LoadConfig loads the configuration from file, environment variables, and command line.
func LoadConfig(log logger.Logger) (*Config, error) {
	v := viper.New()

	// Set default values
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.grpc_port", 50051)
	v.SetDefault("log.level", "info")
	// ... set other defaults

	// Load from config file
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/cbc-auth/")
	v.AddConfigPath(".")
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	// Load from environment variables
	v.SetEnvPrefix("CBC_AUTH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, errors.New("failed to unmarshal config").WithError(err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
//Personal.AI order the ending