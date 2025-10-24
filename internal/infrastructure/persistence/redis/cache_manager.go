package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// CacheManager provides an interface for interacting with the Redis cache.
type CacheManager interface {
	Get(ctx context.Context, key string) (string, *errors.AppError)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *errors.AppError
	Delete(ctx context.Context, key string) *errors.AppError
	Exists(ctx context.Context, key string) (bool, *errors.AppError)

	GetTenantConfig(ctx context.Context, tenantID string) (*models.Tenant, *errors.AppError)
	SetTenantConfig(ctx context.Context, tenant *models.Tenant, ttl time.Duration) *errors.AppError

	AddToBlacklist(ctx context.Context, jti string, ttl time.Duration) *errors.AppError
	IsBlacklisted(ctx context.Context, jti string) (bool, *errors.AppError)
}

type cacheManagerImpl struct {
	redis *RedisConnection
	log   logger.Logger
}

// NewCacheManager creates a new CacheManager.
func NewCacheManager(redis *RedisConnection, log logger.Logger) CacheManager {
	return &cacheManagerImpl{redis: redis, log: log}
}

func (c *cacheManagerImpl) Get(ctx context.Context, key string) (string, *errors.AppError) {
	val, err := c.redis.Client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", errors.ErrNotFound
		}
		return "", errors.ErrCache.WithError(err)
	}
	return val, nil
}

func (c *cacheManagerImpl) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *errors.AppError {
	var dataToStore interface{}
	switch v := value.(type) {
	case string, []byte, int, int32, int64, float32, float64, bool:
		dataToStore = v
	default:
		b, err := json.Marshal(value)
		if err != nil {
			return errors.ErrCache.WithError(err)
		}
		dataToStore = b
	}

	if err := c.redis.Client.Set(ctx, key, dataToStore, ttl).Err(); err != nil {
		return errors.ErrCache.WithError(err)
	}
	return nil
}

func (c *cacheManagerImpl) Delete(ctx context.Context, key string) *errors.AppError {
	if err := c.redis.Client.Del(ctx, key).Err(); err != nil {
		return errors.ErrCache.WithError(err)
	}
	return nil
}

func (c *cacheManagerImpl) Exists(ctx context.Context, key string) (bool, *errors.AppError) {
	val, err := c.redis.Client.Exists(ctx, key).Result()
	if err != nil {
		return false, errors.ErrCache.WithError(err)
	}
	return val > 0, nil
}

func (c *cacheManagerImpl) GetTenantConfig(ctx context.Context, tenantID string) (*models.Tenant, *errors.AppError) {
	key := fmt.Sprintf("tenant:config:%s", tenantID)
	val, err := c.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	var tenant models.Tenant
	if err := json.Unmarshal([]byte(val), &tenant); err != nil {
		return nil, errors.ErrCache.WithError(err)
	}
	return &tenant, nil
}

func (c *cacheManagerImpl) SetTenantConfig(ctx context.Context, tenant *models.Tenant, ttl time.Duration) *errors.AppError {
	key := fmt.Sprintf("tenant:config:%s", tenant.ID)
	return c.Set(ctx, key, tenant, ttl)
}

func (c *cacheManagerImpl) AddToBlacklist(ctx context.Context, jti string, ttl time.Duration) *errors.AppError {
	key := fmt.Sprintf("blacklist:%s", jti)
	return c.Set(ctx, key, "revoked", ttl)
}

func (c *cacheManagerImpl) IsBlacklisted(ctx context.Context, jti string) (bool, *errors.AppError) {
	key := fmt.Sprintf("blacklist:%s", jti)
	return c.Exists(ctx, key)
}
//Personal.AI order the ending