package kms

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/api"
	"github.com/turtacn/cbc/internal/domain/service"
	"golang.org/x/sync/singleflight"
)

type MgrKeyFetcher struct {
	vaultClient *api.Client
	redisClient redis.UniversalClient
	l1Cache     sync.Map
	sf          singleflight.Group
}

func NewMgrKeyFetcher(vaultClient *api.Client, redisClient redis.UniversalClient) *MgrKeyFetcher {
	return &MgrKeyFetcher{
		vaultClient: vaultClient,
		redisClient: redisClient,
	}
}

func (f *MgrKeyFetcher) GetMgrPublicKey(ctx context.Context, clientID, kid string) (*rsa.PublicKey, error) {
	cacheKey := fmt.Sprintf("mgr-key-%s-%s", clientID, kid)

	// L1 Cache (in-memory)
	if key, ok := f.l1Cache.Load(cacheKey); ok {
		return key.(*rsa.PublicKey), nil
	}

	// Single Flight to prevent thundering herd
	key, err, _ := f.sf.Do(cacheKey, func() (interface{}, error) {
		// L2 Cache (Redis)
		if f.redisClient != nil {
			pemData, err := f.redisClient.Get(ctx, cacheKey).Result()
			if err == nil {
				pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pemData))
				if err == nil {
					f.l1Cache.Store(cacheKey, pubKey)
					return pubKey, nil
				}
			}
		}

		// Vault (Source of Truth)
		secret, err := f.vaultClient.KVv2("secret").Get(ctx, fmt.Sprintf("cbc/mgr/%s/public-keys", clientID))
		if err != nil {
			return nil, err
		}

		keysData, ok := secret.Data["keys"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid key data format in vault")
		}

		var keys map[string]string
		if err := json.Unmarshal([]byte(keysData), &keys); err != nil {
			return nil, err
		}

		pemData, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("key with kid %s not found for client %s", kid, clientID)
		}

		pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pemData))
		if err != nil {
			return nil, err
		}

		// Cache the key
		f.l1Cache.Store(cacheKey, pubKey)
		if f.redisClient != nil {
			f.redisClient.Set(ctx, cacheKey, pemData, 1*time.Hour)
		}

		return pubKey, nil
	})

	if err != nil {
		return nil, err
	}

	return key.(*rsa.PublicKey), nil
}

var _ service.MgrKeyFetcher = (*MgrKeyFetcher)(nil)
