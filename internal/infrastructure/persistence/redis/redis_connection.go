package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// RedisConnection manages the Redis client connection.
type RedisConnection struct {
	Client redis.UniversalClient
	log    logger.Logger
}

// NewRedisConnection creates a new Redis client.
// It supports both single-node and cluster configurations.
func NewRedisConnection(cfg *config.RedisConfig, log logger.Logger) (*RedisConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := &redis.UniversalOptions{
		Addrs:        cfg.Addresses,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
	}

	client := redis.NewUniversalClient(opts)

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	log.Info(ctx, "Redis connection created successfully")
	return &RedisConnection{Client: client, log: log}, nil
}

// Ping checks the health of the Redis connection.
func (r *RedisConnection) Ping(ctx context.Context) *errors.AppError {
	if err := r.Client.Ping(ctx).Err(); err != nil {
		return errors.ErrCache.WithError(err)
	}
	return nil
}

// Close gracefully closes the Redis connection.
func (r *RedisConnection) Close() {
	r.log.Info(context.Background(), "Closing Redis connection")
	if err := r.Client.Close(); err != nil {
		r.log.Error(context.Background(), "Failed to close Redis connection", err)
	}
}
//Personal.AI order the ending