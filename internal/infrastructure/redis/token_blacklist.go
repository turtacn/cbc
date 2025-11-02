package redis

import (
  "context"
  "fmt"
  "time"

  "github.com/redis/go-redis/v9"
  "github.com/turtacn/cbc/internal/domain/service"
)

type tokenBlacklist struct{ rdb *redis.Client }

func NewTokenBlacklistStore(rdb *redis.Client) service.TokenBlacklistStore {
  return &tokenBlacklist{rdb: rdb}
}

func key(tenantID, jti string) string { return fmt.Sprintf("cbc:bl:%s:%s", tenantID, jti) }

func (b *tokenBlacklist) Revoke(ctx context.Context, tenantID, jti string, exp time.Time) error {
  ttl := time.Until(exp)
  if ttl <= 0 { return nil }
  return b.rdb.Set(ctx, key(tenantID, jti), "1", ttl).Err()
}

func (b *tokenBlacklist) IsRevoked(ctx context.Context, tenantID, jti string) (bool, error) {
  n, err := b.rdb.Exists(ctx, key(tenantID, jti)).Result()
  if err != nil {
	return false, err
  }
  return n == 1, nil
}
