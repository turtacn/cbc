// internal/infrastructure/persistence/redis/blacklist.go
package redis

import (
   "context"
   "time"

   "github.com/redis/go-redis/v9"
)

type Blacklist struct{
   rdb *redis.Client
}

func NewBlacklist(rdb *redis.Client) *Blacklist { return &Blacklist{rdb: rdb} }

func (b *Blacklist) IsRevoked(jti string) (bool, error) {
   ctx := context.Background()
   exists, err := b.rdb.Exists(ctx, "revoked:"+jti).Result()
   return exists == 1, err
}

func (b *Blacklist) Revoke(jti string) error {
   ctx := context.Background()
   // 保留 30 天
   return b.rdb.Set(ctx, "revoked:"+jti, 1, 30*24*time.Hour).Err()
}
