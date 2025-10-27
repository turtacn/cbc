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

// CacheManager provides high-level caching operations with Redis backend.
type CacheManager struct {
	client    redis.UniversalClient
	logger    logger.Logger
	namespace string
	defaultTTL time.Duration
}

// CacheOptions defines options for cache operations.
type CacheOptions struct {
	// TTL specifies time-to-live for the cache entry
	TTL time.Duration
	// Namespace overrides the default namespace for this operation
	Namespace string
	// NX sets the key only if it does not exist
	NX bool
	// XX sets the key only if it already exists
	XX bool
}

// CacheStats holds cache operation statistics.
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

// NewCacheManager creates a new cache manager instance.
//
// Parameters:
//   - client: Redis client instance
//   - namespace: Default namespace for cache keys
//   - defaultTTL: Default time-to-live for cache entries
//   - log: Logger instance
//
// Returns:
//   - *CacheManager: Initialized cache manager
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

// buildKey constructs a namespaced cache key.
func (cm *CacheManager) buildKey(key string, opts *CacheOptions) string {
	namespace := cm.namespace
	if opts != nil && opts.Namespace != "" {
		namespace = opts.Namespace
	}
	return fmt.Sprintf("%s:%s", namespace, key)
}

// getTTL returns the TTL to use for a cache operation.
func (cm *CacheManager) getTTL(opts *CacheOptions) time.Duration {
	if opts != nil && opts.TTL > 0 {
		return opts.TTL
	}
	return cm.defaultTTL
}

// Set stores a value in cache with optional TTL.
//
// Parameters:
//   - ctx: Context for timeout control
//   - key: Cache key
//   - value: Value to cache (will be JSON serialized)
//   - opts: Cache options (TTL, namespace, etc.)
//
// Returns:
//   - error: Set operation error if any
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

// Get retrieves a value from cache and deserializes it.
//
// Parameters:
//   - ctx: Context for timeout control
//   - key: Cache key
//   - dest: Pointer to destination variable for deserialization
//   - opts: Cache options (namespace)
//
// Returns:
//   - bool: True if key exists
//   - error: Get operation error if any
func (cm *CacheManager) Get(ctx context.Context, key string, dest interface{}, opts *CacheOptions) (bool, error) {
	fullKey := cm.buildKey(key, opts)

	// Get value from Redis
	data, err := cm.client.Get(ctx, fullKey).Bytes()
	if err == redis.Nil {
		cm.logger.Debug(ctx, "Cache miss", logger.String("key", fullKey))
		return false, nil
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

// Delete removes a key from cache.
//
// Parameters:
//   - ctx: Context for timeout control
//   - key: Cache key to delete
//   - opts: Cache options (namespace)
//
// Returns:
//   - error: Delete operation error if any
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

// DeletePattern deletes all keys matching a pattern.
//
// Parameters:
//   - ctx: Context for timeout control
//   - pattern: Key pattern (e.g., "user:*")
//   - opts: Cache options (namespace)
//
// Returns:
//   - int64: Number of keys deleted
//   - error: Delete operation error if any
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

// Exists checks if a key exists in cache.
//
// Parameters:
//   - ctx: Context for timeout control
//   - key: Cache key to check
//   - opts: Cache options (namespace)
//
// Returns:
//   - bool: True if key exists
//   - error: Exists operation error if any
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

// Expire sets a timeout on a key.
//
// Parameters:
//   - ctx: Context for timeout control
//   - key: Cache key
//   - ttl: Time-to-live duration
//   - opts: Cache options (namespace)
//
// Returns:
//   - error: Expire operation error if any
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
//
// Parameters:
//   - ctx: Context for timeout control
//   - key: Cache key
//   - opts: Cache options (namespace)
//
// Returns:
//   - time.Duration: Remaining TTL, -1 if key has no expiry, -2 if key doesn't exist
//   - error: TTL operation error if any
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

// SetMultiple sets multiple key-value pairs in a single operation.
//
// Parameters:
//   - ctx: Context for timeout control
//   - items: Map of key-value pairs
//   - opts: Cache options (TTL, namespace)
//
// Returns:
//   - error: Set operation error if any
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

// GetMultiple retrieves multiple values from cache.
//
// Parameters:
//   - ctx: Context for timeout control
//   - keys: List of cache keys
//   - opts: Cache options (namespace)
//
// Returns:
//   - map[string][]byte: Map of found key-value pairs (as JSON bytes)
//   - error: Get operation error if any
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

// Increment atomically increments a numeric key.
//
// Parameters:
//   - ctx: Context for timeout control
//   - key: Cache key
//   - delta: Increment amount
//   - opts: Cache options (namespace)
//
// Returns:
//   - int64: New value after increment
//   - error: Increment operation error if any
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

// Decrement atomically decrements a numeric key.
//
// Parameters:
//   - ctx: Context for timeout control
//   - key: Cache key
//   - delta: Decrement amount
//   - opts: Cache options (namespace)
//
// Returns:
//   - int64: New value after decrement
//   - error: Decrement operation error if any
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

// Lock acquires a distributed lock.
//
// Parameters:
//   - ctx: Context for timeout control
//   - key: Lock key
//   - ttl: Lock expiration time
//   - opts: Cache options (namespace)
//
// Returns:
//   - bool: True if lock acquired
//   - error: Lock operation error if any
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

// Unlock releases a distributed lock.
//
// Parameters:
//   - ctx: Context for timeout control
//   - key: Lock key
//   - opts: Cache options (namespace)
//
// Returns:
//   - error: Unlock operation error if any
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

// FlushNamespace deletes all keys in the current namespace.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - int64: Number of keys deleted
//   - error: Flush operation error if any
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

// GetStats retrieves cache statistics.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - *CacheStats: Cache statistics
//   - error: Stats operation error if any
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
			break
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

// Ping checks Redis connectivity.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - error: Ping error if any
func (cm *CacheManager) Ping(ctx context.Context) error {
	return cm.client.Ping(ctx).Err()
}
