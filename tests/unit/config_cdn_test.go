//go:build unit

package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/turtacn/cbc/internal/config"
)

const (
	testConfigPath = "../../../config/config.test.yaml"
)

// Test_LoadCDNConfig_Default_Stubbed tests that the default configuration
// correctly loads with the CDN purge disabled and sets up the stub.
func Test_LoadCDNConfig_Default_Stubbed(t *testing.T) {
	// Setup: create a temporary config file for the test
	configContent := `
database:
  password: "testpassword"
kafka:
  brokers: ["localhost:9092"]
  audit_topic: "test-topic"
  batch_size: 1
oauth:
  device_auth_expires_in: 10m
  device_auth_interval: 5s
  verification_uri: "https://example.com/verify"
cdn:
  purge_enabled: false
  provider: "stub"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0600)
	require.NoError(t, err, "failed to write test config file")

	// Execute: load the configuration
	cfg, err := config.LoadFromFile(configPath, nil)
	require.NoError(t, err, "config loader failed")

	// Verify: check that CDN config is loaded correctly and is disabled
	assert.False(t, cfg.CDN.PurgeEnabled, "CDN purge should be disabled by default")
	assert.Equal(t, "stub", cfg.CDN.Provider, "CDN provider should be 'stub' by default")
}

// Test_LoadCDNConfig_AWS_CloudFront_Enabled tests loading a configuration
// where AWS CloudFront is enabled as the CDN provider.
func Test_LoadCDNConfig_AWS_CloudFront_Enabled(t *testing.T) {
	// Setup: create a temporary config file with CloudFront enabled
	configContent := `
database:
  password: "testpassword"
kafka:
  brokers: ["localhost:9092"]
  audit_topic: "test-topic"
  batch_size: 1
oauth:
  device_auth_expires_in: 10m
  device_auth_interval: 5s
  verification_uri: "https://example.com/verify"
cdn:
  purge_enabled: true
  provider: "aws_cloudfront"
  distribution_id: "E1234567890"
  api_token_env_var: "CDN_API_TOKEN"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0600)
	require.NoError(t, err, "failed to write test config file")

	// Execute: load the configuration
	cfg, err := config.LoadFromFile(configPath, nil)
	require.NoError(t, err, "config loader failed")

	// Verify: check that CloudFront settings are correctly loaded
	assert.True(t, cfg.CDN.PurgeEnabled, "CDN purge should be enabled")
	assert.Equal(t, "aws_cloudfront", cfg.CDN.Provider, "CDN provider should be 'aws_cloudfront'")
	assert.Equal(t, "E1234567890", cfg.CDN.DistributionID, "Incorrect CloudFront Distribution ID")
	assert.Equal(t, "CDN_API_TOKEN", cfg.CDN.APITokenEnvVar, "Incorrect API token env var")
}

// Test_CDNConfig_Validate_Success validates a correct CDN configuration.
func Test_CDNConfig_Validate_Success(t *testing.T) {
	cfg := &config.CDNConfig{
		PurgeEnabled:   true,
		Provider:       "aws_cloudfront",
		DistributionID: "DIST_ID_123",
	}
	err := cfg.Validate()
	assert.NoError(t, err, "validation should pass for correct config")
}

// Test_CDNConfig_Validate_Failure_Missing_DistributionID tests validation failure
// when the distribution ID is missing for the aws_cloudfront provider.
func Test_CDNConfig_Validate_Failure_Missing_DistributionID(t *testing.T) {
	cfg := &config.CDNConfig{
		PurgeEnabled: true,
		Provider:     "aws_cloudfront",
	}
	err := cfg.Validate()
	assert.Error(t, err, "validation should fail without distribution ID")
	assert.True(t, strings.Contains(err.Error(), "distribution ID is required"), "error message mismatch")
}

// Test_CDNConfig_Validate_Unsupported_Provider tests validation for an unsupported provider.
func Test_CDNConfig_Validate_Unsupported_Provider(t *testing.T) {
	cfg := &config.CDNConfig{
		PurgeEnabled: true,
		Provider:     "unsupported_cdn",
	}
	err := cfg.Validate()
	assert.Error(t, err, "validation should fail for unsupported provider")
	assert.True(t, strings.Contains(err.Error(), "unsupported cdn provider"), "error message mismatch")
}
