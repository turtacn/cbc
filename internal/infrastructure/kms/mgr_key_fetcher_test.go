package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey() (*rsa.PrivateKey, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	return priv, pubPEM
}

func TestMgrKeyFetcher_GetMgrPublicKey(t *testing.T) {
	_, pubPEM := generateTestKey()
	clientID := "test-client"
	kid := "test-kid"

	// Mock Vault Server
	vaultMux := http.NewServeMux()
	vaultMux.HandleFunc(fmt.Sprintf("/v1/secret/data/cbc/mgr/%s/public-keys", clientID), func(w http.ResponseWriter, r *http.Request) {
		keys := map[string]string{kid: string(pubPEM)}
		keysData, _ := json.Marshal(keys)
		secretData := map[string]interface{}{
			"data": map[string]interface{}{
				"keys": string(keysData),
			},
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": secretData})
	})
	vaultServer := httptest.NewServer(vaultMux)
	defer vaultServer.Close()

	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = vaultServer.URL
	vaultClient, err := api.NewClient(vaultConfig)
	require.NoError(t, err)

	// Mock Redis Server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	fetcher := NewMgrKeyFetcher(vaultClient, redisClient)

	// 1. Cache Miss (Vault Hit)
	t.Run("cache miss", func(t *testing.T) {
		key, err := fetcher.GetMgrPublicKey(context.Background(), clientID, kid)
		require.NoError(t, err)
		assert.NotNil(t, key)

		// Check L1 Cache
		_, ok := fetcher.l1Cache.Load(fmt.Sprintf("mgr-key-%s-%s", clientID, kid))
		assert.True(t, ok, "key should be in L1 cache")

		// Check L2 Cache
		cachedPEM, err := redisClient.Get(context.Background(), fmt.Sprintf("mgr-key-%s-%s", clientID, kid)).Result()
		assert.NoError(t, err)
		assert.Equal(t, string(pubPEM), cachedPEM, "key should be in L2 cache")
	})

	// 2. L1 Cache Hit
	t.Run("l1 cache hit", func(t *testing.T) {
		// Stop servers to ensure we're not hitting them
		vaultServer.Close()
		mr.Close()

		key, err := fetcher.GetMgrPublicKey(context.Background(), clientID, kid)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	// 3. L2 Cache Hit
	t.Run("l2 cache hit", func(t *testing.T) {
		// Restart Redis, keep Vault down
		mr, err := miniredis.Run()
		require.NoError(t, err)
		defer mr.Close()
		redisClient = redis.NewClient(&redis.Options{Addr: mr.Addr()})

		// Manually populate L2
		err = redisClient.Set(context.Background(), fmt.Sprintf("mgr-key-%s-%s", clientID, kid), string(pubPEM), 1*time.Hour).Err()
		require.NoError(t, err)

		// New fetcher with empty L1
		fetcherL2 := NewMgrKeyFetcher(vaultClient, redisClient)

		key, err := fetcherL2.GetMgrPublicKey(context.Background(), clientID, kid)
		require.NoError(t, err)
		assert.NotNil(t, key)

		// Check L1 is now populated
		_, ok := fetcherL2.l1Cache.Load(fmt.Sprintf("mgr-key-%s-%s", clientID, kid))
		assert.True(t, ok, "key should now be in L1 cache after L2 hit")
	})
}
