// Package redis provides caching functionality using Redis as the backend.
// It includes cache operations, serialization, key management, and distributed locking.
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/turtacn/cbc/pkg/logger"
)

// CacheManager provides a high-level abstraction for caching operations backed by Redis.
// It handles key namespacing, serialization/deserialization, and common caching patterns.
// CacheManager 提供了由 Redis 支持的缓存操作的高级抽象。
// 它处理密钥命名空间、序列化/反序列化和常见的缓存模式。
type CacheManager struct {
	client     redis.UniversalClient
	logger     logger.Logger
	namespace  string
	defaultTTL time.Duration
}

// CacheOptions defines configurable options for individual cache operations.
// CacheOptions 定义了单个缓存操作的可配置选项。
type CacheOptions struct {
	// TTL specifies a custom time-to-live for a specific cache entry, overriding the default.
	// TTL 为特定缓存条目指定自定义的生存时间，覆盖默认值。
	TTL time.Duration
	// Namespace allows overriding the default namespace for a specific operation.
	// Namespace 允许为特定操作覆盖默认的命名空间。
	Namespace string
	// NX (Not Exists) sets the key only if it does not already exist.
	// NX (Not Exists) 仅在密钥不存在时才设置该密钥。
	NX bool
	// XX (Exists) sets the key only if it already exists.
	// XX (Exists) 仅在密钥已存在时才设置该密钥。
	XX bool
}

// CacheStats holds various statistics about cache performance and usage.
// CacheStats 保存有关缓存性能和使用情况的各种统计信息。
type CacheStats struct {
	Hits        int64         `json:"hits"`
	Misses      int64         `json:"misses"`
	Sets        int64         `json:"sets"`
	Deletes     int64         `json:"deletes"`
	Errors      int64         `json:"errors"`
	TotalKeys   int64         `json:"total_keys"`
	MemoryUsage int64         `json:"memory_usage_bytes"`
	HitRate     float64       `json:"hit_rate"`
	AvgLatency  time.Duration `json:"avg_latency"`
}

// NewCacheManager creates and initializes a new CacheManager instance.
// NewCacheManager 创建并初始化一个新的 CacheManager 实例。
//
// Parameters:
//   - client: An underlying Redis client (UniversalClient for cluster/sentinel/single-node support).
//   - namespace: A default prefix for all cache keys to avoid collisions.
//   - defaultTTL: The default expiration time for cache entries if not otherwise specified.
//   - log: A logger instance for logging cache operations and errors.
//
// Returns:
//   - *CacheManager: A pointer to the newly created CacheManager.
func NewCacheManager(
	client redis.UniversalClient,
	namespace string,
	defaultTTL time.Duration,
	log logger.Logger,
) *CacheManager {
	return &CacheManager{
		client:     client,
		logger:     log,
		namespace:  namespace,
		defaultTTL: defaultTTL,
	}
}

// buildKey constructs a final cache key by prepending the configured namespace.
// It allows for a namespace override via CacheOptions.
// buildKey 通过在前面添加配置的命名空间来构造最终的缓存密钥。
// 它允许通过 CacheOptions 覆盖命名空间。
func (cm *CacheManager) buildKey(key string, opts *CacheOptions) string {
	namespace := cm.namespace
	if opts != nil && opts.Namespace != "" {
		namespace = opts.Namespace
	}
	return fmt.Sprintf("%s:%s", namespace, key)
}

// getTTL determines the appropriate TTL for a cache operation,
// prioritizing the TTL from CacheOptions and falling back to the default.
// getTTL 确定缓存操作的适当 TTL，优先使用 CacheOptions 中的 TTL，然后回退到默认值。
func (cm *CacheManager) getTTL(opts *CacheOptions) time.Duration {
	if opts != nil && opts.TTL > 0 {
		return opts.TTL
	}
	return cm.defaultTTL
}

// Set stores a value in the cache. The value is JSON serialized before storing.
// It supports conditional operations like Set-if-not-exists (NX) or Set-if-exists (XX).
// Set 将一个值存储在缓存中。该值在存储前会被 JSON 序列化。
// 它支持条件操作，如 Set-if-not-exists (NX) 或 Set-if-exists (XX)。
func (cm *CacheManager) Set(ctx context.Context, key string, value interface{}, opts *CacheOptions) error {
	fullKey := cm.buildKey(key, opts)
	ttl := cm.getTTL(opts)

	// Serialize value to JSON
	data, err := json.Marshal(value)
	if err != nil {
		cm.logger.Error(ctx, "Failed to marshal cache value", err,
			logger.String("key", key),
		)
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	// Prepare set arguments
	var setArgs redis.SetArgs
	setArgs.TTL = ttl

	if opts != nil {
		if opts.NX {
			setArgs.Mode = "NX" // Set if not exists
		} else if opts.XX {
			setArgs.Mode = "XX" // Set if exists
		}
	}

	// Set value in Redis
	if err := cm.client.SetArgs(ctx, fullKey, data, setArgs).Err(); err != nil {
		cm.logger.Error(ctx, "Failed to set cache value", err,
			logger.String("key", fullKey),
			logger.Duration("ttl", ttl),
		)
		return fmt.Errorf("failed to set cache: %w", err)
	}

	cm.logger.Debug(ctx, "Cache value set successfully",
		logger.String("key", fullKey),
		logger.Duration("ttl", ttl),
	)

	return nil
}

// Get retrieves a value from the cache and deserializes it from JSON into the `dest` variable.
// `dest` must be a pointer to the target data structure.
// It returns `true` if the key was found (a cache hit), and `false` otherwise (a cache miss).
// Get 从缓存中检索一个值，并将其从 JSON 反序列化到 `dest` 变量中。
// `dest` 必须是指向目标数据结构的指针。
// 如果找到密钥（缓存命中），则返回 `true`，否则返回 `false`（缓存未命中）。
func (cm *CacheManager) Get(ctx context.Context, key string, dest interface{}, opts *CacheOptions) (bool, error) {
	fullKey := cm.buildKey(key, opts)

	// Get value from Redis
	data, err := cm.client.Get(ctx, fullKey).Bytes()
	if err == redis.Nil {
		cm.logger.Debug(ctx, "Cache miss", logger.String("key", fullKey))
		return false, nil // Cache miss, not an error
	}
	if err != nil {
		cm.logger.Error(ctx, "Failed to get cache value", err,
			logger.String("key", fullKey),
		)
		return false, fmt.Errorf("failed to get cache: %w", err)
	}

	// Deserialize JSON
	if err := json.Unmarshal(data, dest); err != nil {
		cm.logger.Error(ctx, "Failed to unmarshal cache value", err,
			logger.String("key", fullKey),
		)
		return false, fmt.Errorf("failed to unmarshal value: %w", err)
	}

	cm.logger.Debug(ctx, "Cache hit", logger.String("key", fullKey))
	return true, nil
}

// Delete removes a key from the cache.
// Delete 从缓存中删除一个密钥。
func (cm *CacheManager) Delete(ctx context.Context, key string, opts *CacheOptions) error {
	fullKey := cm.buildKey(key, opts)

	if err := cm.client.Del(ctx, fullKey).Err(); err != nil {
		cm.logger.Error(ctx, "Failed to delete cache key", err,
			logger.String("key", fullKey),
		)
		return fmt.Errorf("failed to delete cache: %w", err)
	}

	cm.logger.Debug(ctx, "Cache key deleted", logger.String("key", fullKey))
	return nil
}

// DeletePattern removes all keys from the cache that match a given pattern.
// This operation can be slow and should be used with caution in production environments.
// DeletePattern 从缓存中删除所有与给定模式匹配的密钥。
// 此操作可能很慢，在生产环境中应谨慎使用。
func (cm *CacheManager) DeletePattern(ctx context.Context, pattern string, opts *CacheOptions) (int64, error) {
	fullPattern := cm.buildKey(pattern, opts)

	var cursor uint64
	var deletedCount int64

	for {
		// Scan for keys matching pattern
		keys, nextCursor, err := cm.client.Scan(ctx, cursor, fullPattern, 100).Result()
		if err != nil {
			cm.logger.Error(ctx, "Failed to scan keys", err,
				logger.String("pattern", fullPattern),
			)
			return deletedCount, fmt.Errorf("failed to scan keys: %w", err)
		}

		// Delete found keys
		if len(keys) > 0 {
			deleted, err := cm.client.Del(ctx, keys...).Result()
			if err != nil {
				cm.logger.Error(ctx, "Failed to delete keys", err,
					logger.String("pattern", fullPattern),
				)
				return deletedCount, fmt.Errorf("failed to delete keys: %w", err)
			}
			deletedCount += deleted
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	cm.logger.Info(ctx, "Deleted keys by pattern",
		logger.String("pattern", fullPattern),
		logger.Int64("count", deletedCount),
	)

	return deletedCount, nil
}

// Exists checks for the existence of a key in the cache.
// Exists 检查缓存中是否存在密钥。
func (cm *CacheManager) Exists(ctx context.Context, key string, opts *CacheOptions) (bool, error) {
	fullKey := cm.buildKey(key, opts)

	count, err := cm.client.Exists(ctx, fullKey).Result()
	if err != nil {
		cm.logger.Error(ctx, "Failed to check key existence", err,
			logger.String("key", fullKey),
		)
		return false, fmt.Errorf("failed to check existence: %w", err)
	}

	return count > 0, nil
}

// Expire sets a new expiration time for an existing key.
// Expire 为现有密钥设置新的过期时间。
func (cm *CacheManager) Expire(ctx context.Context, key string, ttl time.Duration, opts *CacheOptions) error {
	fullKey := cm.buildKey(key, opts)

	if err := cm.client.Expire(ctx, fullKey, ttl).Err(); err != nil {
		cm.logger.Error(ctx, "Failed to set key expiration", err,
			logger.String("key", fullKey),
			logger.Duration("ttl", ttl),
		)
		return fmt.Errorf("failed to set expiration: %w", err)
	}

	cm.logger.Debug(ctx, "Key expiration set",
		logger.String("key", fullKey),
		logger.Duration("ttl", ttl),
	)

	return nil
}

// TTL returns the remaining time-to-live of a key.
// It returns specific negative values if the key does not exist or has no expiry.
// TTL 返回密钥的剩余生存时间。
// 如果密钥不存在或没有过期时间，它将返回特定的负值。
func (cm *CacheManager) TTL(ctx context.Context, key string, opts *CacheOptions) (time.Duration, error) {
	fullKey := cm.buildKey(key, opts)

	ttl, err := cm.client.TTL(ctx, fullKey).Result()
	if err != nil {
		cm.logger.Error(ctx, "Failed to get key TTL", err,
			logger.String("key", fullKey),
		)
		return 0, fmt.Errorf("failed to get TTL: %w", err)
	}

	return ttl, nil
}

// SetMultiple stores multiple key-value pairs in a single, pipelined operation for efficiency.
// All items will have the same TTL.
// SetMultiple 通过单个流水线操作高效地存储多个键值对。
// 所有项目将具有相同的 TTL。
func (cm *CacheManager) SetMultiple(ctx context.Context, items map[string]interface{}, opts *CacheOptions) error {
	pipe := cm.client.Pipeline()
	ttl := cm.getTTL(opts)

	for key, value := range items {
		fullKey := cm.buildKey(key, opts)

		data, err := json.Marshal(value)
		if err != nil {
			cm.logger.Error(ctx, "Failed to marshal cache value", err,
				logger.String("key", key),
			)
			return fmt.Errorf("failed to marshal value for key %s: %w", key, err)
		}

		pipe.Set(ctx, fullKey, data, ttl)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		cm.logger.Error(ctx, "Failed to execute pipeline for multiple sets", err,
			logger.Int("count", len(items)),
		)
		return fmt.Errorf("failed to set multiple values: %w", err)
	}

	cm.logger.Debug(ctx, "Multiple cache values set",
		logger.Int("count", len(items)),
		logger.Duration("ttl", ttl),
	)

	return nil
}

// GetMultiple retrieves multiple values from the cache in a single, pipelined operation.
// It returns a map of found keys to their raw JSON byte values. Keys not found are omitted from the result.
// GetMultiple 通过单个流水线操作从缓存中检索多个值。
// 它返回一个将找到的密钥映射到其原始 JSON 字节值的映射。未找到的密钥将从结果中省略。
func (cm *CacheManager) GetMultiple(ctx context.Context, keys []string, opts *CacheOptions) (map[string][]byte, error) {
	if len(keys) == 0 {
		return make(map[string][]byte), nil
	}

	// Build full keys
	fullKeys := make([]string, len(keys))
	keyMap := make(map[string]string) // fullKey -> originalKey
	for i, key := range keys {
		fullKey := cm.buildKey(key, opts)
		fullKeys[i] = fullKey
		keyMap[fullKey] = key
	}

	// Get values using pipeline
	pipe := cm.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(fullKeys))
	for i, fullKey := range fullKeys {
		cmds[i] = pipe.Get(ctx, fullKey)
	}

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		cm.logger.Error(ctx, "Failed to execute pipeline for multiple gets", err,
			logger.Int("count", len(keys)),
		)
		return nil, fmt.Errorf("failed to get multiple values: %w", err)
	}

	// Collect results
	results := make(map[string][]byte)
	for i, cmd := range cmds {
		data, err := cmd.Bytes()
		if err == redis.Nil {
			continue // Key not found, skip
		}
		if err != nil {
			cm.logger.Warn(ctx, "Failed to get value for key",
				logger.String("key", fullKeys[i]),
			)
			continue
		}

		originalKey := keyMap[fullKeys[i]]
		results[originalKey] = data
	}

	cm.logger.Debug(ctx, "Multiple cache values retrieved",
		logger.Int("requested", len(keys)),
		logger.Int("found", len(results)),
	)

	return results, nil
}

// Increment atomically increments the integer value of a key by a given delta.
// If the key does not exist, it is set to 0 before the operation.
// Increment 原子地将密钥的整数值增加给定的增量。
// 如果密钥不存在，它将在操作前被设置为 0。
func (cm *CacheManager) Increment(ctx context.Context, key string, delta int64, opts *CacheOptions) (int64, error) {
	fullKey := cm.buildKey(key, opts)

	newValue, err := cm.client.IncrBy(ctx, fullKey, delta).Result()
	if err != nil {
		cm.logger.Error(ctx, "Failed to increment key", err,
			logger.String("key", fullKey),
			logger.Int64("delta", delta),
		)
		return 0, fmt.Errorf("failed to increment: %w", err)
	}

	cm.logger.Debug(ctx, "Key incremented",
		logger.String("key", fullKey),
		logger.Int64("delta", delta),
		logger.Int64("new_value", newValue),
	)

	return newValue, nil
}

// Decrement atomically decrements the integer value of a key by a given delta.
// If the key does not exist, it is set to 0 before the operation.
// Decrement 原子地将密钥的整数值减少给定的增量。
// 如果密钥不存在，它将在操作前被设置为 0。
func (cm *CacheManager) Decrement(ctx context.Context, key string, delta int64, opts *CacheOptions) (int64, error) {
	fullKey := cm.buildKey(key, opts)

	newValue, err := cm.client.DecrBy(ctx, fullKey, delta).Result()
	if err != nil {
		cm.logger.Error(ctx, "Failed to decrement key", err,
			logger.String("key", fullKey),
			logger.Int64("delta", delta),
		)
		return 0, fmt.Errorf("failed to decrement: %w", err)
	}

	cm.logger.Debug(ctx, "Key decremented",
		logger.String("key", fullKey),
		logger.Int64("delta", delta),
		logger.Int64("new_value", newValue),
	)

	return newValue, nil
}

// Lock attempts to acquire a distributed lock with a specified TTL.
// It returns `true` if the lock was successfully acquired, and `false` if the lock is already held.
// This is a non-blocking lock attempt.
// Lock 尝试获取具有指定 TTL 的分布式锁。
// 如果成功获取锁，则返回 `true`；如果锁已被持有，则返回 `false`。
// 这是一个非阻塞的锁尝试。
func (cm *CacheManager) Lock(ctx context.Context, key string, ttl time.Duration, opts *CacheOptions) (bool, error) {
	fullKey := cm.buildKey("lock:"+key, opts)

	// Try to set the lock with NX option
	acquired, err := cm.client.SetNX(ctx, fullKey, "1", ttl).Result()
	if err != nil {
		cm.logger.Error(ctx, "Failed to acquire lock", err,
			logger.String("key", fullKey),
			logger.Duration("ttl", ttl),
		)
		return false, fmt.Errorf("failed to acquire lock: %w", err)
	}

	if acquired {
		cm.logger.Debug(ctx, "Lock acquired",
			logger.String("key", fullKey),
			logger.Duration("ttl", ttl),
		)
	} else {
		cm.logger.Debug(ctx, "Lock already held", logger.String("key", fullKey))
	}

	return acquired, nil
}

// Unlock releases a previously acquired distributed lock.
// It's important that the service that acquired the lock is the one to release it.
// Unlock 释放先前获取的分布式锁。
// 获取锁的服务必须是释放锁的服务，这一点很重要。
func (cm *CacheManager) Unlock(ctx context.Context, key string, opts *CacheOptions) error {
	fullKey := cm.buildKey("lock:"+key, opts)

	if err := cm.client.Del(ctx, fullKey).Err(); err != nil {
		cm.logger.Error(ctx, "Failed to release lock", err,
			logger.String("key", fullKey),
		)
		return fmt.Errorf("failed to release lock: %w", err)
	}

	cm.logger.Debug(ctx, "Lock released", logger.String("key", fullKey))
	return nil
}

// FlushNamespace deletes all keys within the manager's default namespace.
// This is a potentially destructive operation and should be used with care.
// FlushNamespace 删除管理器默认命名空间内的所有密钥。
// 这是一个潜在的破坏性操作，应谨慎使用。
func (cm *CacheManager) FlushNamespace(ctx context.Context) (int64, error) {
	count, err := cm.DeletePattern(ctx, "*", nil)
	if err != nil {
		return 0, err
	}

	cm.logger.Info(ctx, "Namespace flushed",
		logger.String("namespace", cm.namespace),
		logger.Int64("count", count),
	)

	return count, nil
}

// GetStats retrieves statistics about the cache's performance, such as hits, misses, and hit rate.
// Note: This can be an expensive operation, especially for calculating total keys in a large namespace.
// GetStats 检索有关缓存性能的统计信息，例如命中、未命中和命中率。
// 注意：这可能是一个昂贵的操作，尤其是在计算大命名空间中的总密钥数时。
func (cm *CacheManager) GetStats(ctx context.Context) (*CacheStats, error) {
	stats := &CacheStats{}

	// Get pool statistics
	poolStats := cm.client.PoolStats()
	stats.Hits = int64(poolStats.Hits)
	stats.Misses = int64(poolStats.Misses)

	// Calculate hit rate
	totalRequests := stats.Hits + stats.Misses
	if totalRequests > 0 {
		stats.HitRate = float64(stats.Hits) / float64(totalRequests)
	}

	// Get key count for namespace
	pattern := fmt.Sprintf("%s:*", cm.namespace)
	var cursor uint64
	var keyCount int64

	for {
		keys, nextCursor, err := cm.client.Scan(ctx, cursor, pattern, 1000).Result()
		if err != nil {
			cm.logger.Error(ctx, "Failed to scan keys for stats", err)
			break // Exit loop on scan error, but return partial stats
		}

		keyCount += int64(len(keys))
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	stats.TotalKeys = keyCount

	cm.logger.Debug(ctx, "Cache stats retrieved",
		logger.Int64("total_keys", stats.TotalKeys),
		logger.Float64("hit_rate", stats.HitRate),
	)

	return stats, nil
}

// Ping checks the connectivity to the Redis server.
// It is useful for health checks.
// Ping 检查与 Redis 服务器的连接性。
// 它对于健康检查很有用。
func (cm *CacheManager) Ping(ctx context.Context) error {
	return cm.client.Ping(ctx).Err()
}
