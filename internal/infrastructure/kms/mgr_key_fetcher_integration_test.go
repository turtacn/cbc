//go:build integration
package kms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"os"
)

func requireDockerOrSkip(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skip("Docker socket not accessible; skipping integration test")
	}
}

func setupVault(ctx context.Context, t *testing.T) (*api.Client, testcontainers.Container) {
	req := testcontainers.ContainerRequest{
		Image:        "vault:1.9.3",
		ExposedPorts: []string{"8200/tcp"},
		Env: map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID": "root",
		},
		WaitingFor: wait.ForHTTP("/v1/sys/health").WithStatusCodeMatcher(func(status int) bool {
			return status == http.StatusOK
		}),
	}
	vaultC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := vaultC.Host(ctx)
	require.NoError(t, err)
	port, err := vaultC.MappedPort(ctx, "8200")
	require.NoError(t, err)

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("http://%s:%s", host, port.Port())
	client, err := api.NewClient(config)
	require.NoError(t, err)
	client.SetToken("root")

	// Enable KV v2 engine
	err = client.Sys().Mount("secret", &api.MountInput{Type: "kv-v2"})
	require.NoError(t, err)

	return client, vaultC
}

func setupRedis(ctx context.Context, t *testing.T) (*redis.Client, testcontainers.Container) {
	req := testcontainers.ContainerRequest{
		Image:        "redis:6.2-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}
	redisC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := redisC.Host(ctx)
	require.NoError(t, err)
	port, err := redisC.MappedPort(ctx, "6379")
	require.NoError(t, err)

	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", host, port.Port()),
	})
	return client, redisC
}

func TestMgrKeyFetcher_Integration(t *testing.T) {
	if os.Getenv("SKIP_DOCKER_TESTS") != "" {
		t.Skip("Skipping Docker-dependent tests")
	}
	ctx := context.Background()
	vaultClient, vaultC := setupVault(ctx, t)
	defer vaultC.Terminate(ctx)
	redisClient, redisC := setupRedis(ctx, t)
	defer redisC.Terminate(ctx)

	_, pubPEM := generateTestKey()
	clientID := "mgr-e2e-client"
	kid := "e2e-kid"

	keys := map[string]string{kid: string(pubPEM)}
	keysData, _ := json.Marshal(keys)
	secretData := map[string]interface{}{
		"keys": string(keysData),
	}
	_, err := vaultClient.KVv2("secret").Put(ctx, fmt.Sprintf("cbc/mgr/%s/public-keys", clientID), secretData)
	require.NoError(t, err)

	fetcher := NewMgrKeyFetcher(vaultClient, redisClient)

	// 1. First call, should hit Vault and populate caches
	key, err := fetcher.GetMgrPublicKey(ctx, clientID, kid)
	require.NoError(t, err)
	assert.NotNil(t, key)

	// 2. Second call, should hit L1 cache (verify by checking Redis TTL)
	key, err = fetcher.GetMgrPublicKey(ctx, clientID, kid)
	require.NoError(t, err)
	assert.NotNil(t, key)
	ttl, err := redisClient.TTL(ctx, fmt.Sprintf("mgr-key-%s-%s", clientID, kid)).Result()
	require.NoError(t, err)
	assert.InDelta(t, (1 * time.Hour).Seconds(), ttl.Seconds(), 2)

	// 3. Third call on new fetcher, should hit L2 cache
	fetcher2 := NewMgrKeyFetcher(vaultClient, redisClient)
	key, err = fetcher2.GetMgrPublicKey(ctx, clientID, kid)
	require.NoError(t, err)
	assert.NotNil(t, key)
}
