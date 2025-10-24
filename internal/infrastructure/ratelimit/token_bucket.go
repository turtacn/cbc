// Package ratelimit provides rate limiting implementations.
package ratelimit

import (
	"sync"
	"time"

	"github.com/turtacn/cbc/pkg/constants"
)

// TokenBucket implements the token bucket algorithm for rate limiting.
// It provides thread-safe rate limiting with automatic token refill.
type TokenBucket struct {
	mu         sync.Mutex
	capacity   float64   // Maximum number of tokens
	tokens     float64   // Current number of tokens
	rate       float64   // Tokens added per second
	lastRefill time.Time // Last time tokens were refilled
}

// TokenBucketConfig holds configuration for creating a token bucket.
type TokenBucketConfig struct {
	// Capacity is the maximum number of tokens the bucket can hold
	Capacity float64
	// Rate is the number of tokens added per second
	Rate float64
}

// NewTokenBucket creates a new token bucket with the specified capacity and rate.
//
// Parameters:
//   - capacity: Maximum number of tokens the bucket can hold
//   - rate: Number of tokens added per second
//
// Returns:
//   - *TokenBucket: Initialized token bucket
func NewTokenBucket(capacity, rate float64) *TokenBucket {
	if capacity <= 0 {
		capacity = float64(constants.DefaultRateLimitPerMinute)
	}
	if rate <= 0 {
		rate = float64(constants.DefaultRateLimitPerMinute) / 60.0 // per second
	}

	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity, // Start with full bucket
		rate:       rate,
		lastRefill: time.Now(),
	}
}

// Allow attempts to consume one token from the bucket.
// Returns true if a token was available, false otherwise.
//
// Returns:
//   - bool: true if request is allowed, false otherwise
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1.0)
}

// AllowN attempts to consume n tokens from the bucket.
// Returns true if enough tokens were available, false otherwise.
//
// Parameters:
//   - n: Number of tokens to consume
//
// Returns:
//   - bool: true if request is allowed, false otherwise
func (tb *TokenBucket) AllowN(n float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Refill tokens based on elapsed time
	tb.refill()

	// Check if we have enough tokens
	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}

	return false
}

// refill adds tokens to the bucket based on elapsed time since last refill.
// Must be called with lock held.
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()

	// Calculate tokens to add
	tokensToAdd := elapsed * tb.rate

	// Add tokens, but don't exceed capacity
	tb.tokens += tokensToAdd
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	tb.lastRefill = now
}

// Available returns the current number of tokens available.
//
// Returns:
//   - float64: Number of available tokens
func (tb *TokenBucket) Available() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	return tb.tokens
}

// Capacity returns the maximum capacity of the bucket.
//
// Returns:
//   - float64: Maximum capacity
func (tb *TokenBucket) Capacity() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.capacity
}

// Rate returns the refill rate of the bucket.
//
// Returns:
//   - float64: Refill rate (tokens per second)
func (tb *TokenBucket) Rate() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.rate
}

// SetCapacity updates the bucket capacity.
//
// Parameters:
//   - capacity: New capacity value
func (tb *TokenBucket) SetCapacity(capacity float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.capacity = capacity
	if tb.tokens > capacity {
		tb.tokens = capacity
	}
}

// SetRate updates the refill rate.
//
// Parameters:
//   - rate: New rate value (tokens per second)
func (tb *TokenBucket) SetRate(rate float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.rate = rate
}

// Reset resets the bucket to full capacity.
func (tb *TokenBucket) Reset() {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.tokens = tb.capacity
	tb.lastRefill = time.Now()
}

// TimeUntilAvailable returns the duration until n tokens will be available.
//
// Parameters:
//   - n: Number of tokens needed
//
// Returns:
//   - time.Duration: Time until tokens are available
func (tb *TokenBucket) TimeUntilAvailable(n float64) time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= n {
		return 0
	}

	tokensNeeded := n - tb.tokens
	seconds := tokensNeeded / tb.rate
	return time.Duration(seconds * float64(time.Second))
}

// Stats returns current bucket statistics.
//
// Returns:
//   - TokenBucketStats: Current statistics
func (tb *TokenBucket) Stats() TokenBucketStats {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	return TokenBucketStats{
		Capacity:   tb.capacity,
		Available:  tb.tokens,
		Rate:       tb.rate,
		Usage:      (tb.capacity - tb.tokens) / tb.capacity * 100,
		LastRefill: tb.lastRefill,
	}
}

// TokenBucketStats holds statistics about a token bucket.
type TokenBucketStats struct {
	// Capacity is the maximum number of tokens
	Capacity float64
	// Available is the current number of tokens
	Available float64
	// Rate is the refill rate (tokens per second)
	Rate float64
	// Usage is the percentage of capacity used (0-100)
	Usage float64
	// LastRefill is the last refill timestamp
	LastRefill time.Time
}

// TokenBucketPool manages multiple token buckets with automatic cleanup.
type TokenBucketPool struct {
	mu      sync.RWMutex
	buckets map[string]*tokenBucketEntry
	config  TokenBucketConfig
}

// tokenBucketEntry wraps a token bucket with metadata.
type tokenBucketEntry struct {
	bucket   *TokenBucket
	lastUsed time.Time
}

// NewTokenBucketPool creates a new token bucket pool.
//
// Parameters:
//   - config: Default configuration for new buckets
//
// Returns:
//   - *TokenBucketPool: Initialized pool
func NewTokenBucketPool(config TokenBucketConfig) *TokenBucketPool {
	return &TokenBucketPool{
		buckets: make(map[string]*tokenBucketEntry),
		config:  config,
	}
}

// GetOrCreate gets an existing bucket or creates a new one.
//
// Parameters:
//   - key: Unique identifier for the bucket
//
// Returns:
//   - *TokenBucket: The token bucket instance
func (p *TokenBucketPool) GetOrCreate(key string) *TokenBucket {
	// Try read lock first for performance
	p.mu.RLock()
	if entry, exists := p.buckets[key]; exists {
		entry.lastUsed = time.Now()
		p.mu.RUnlock()
		return entry.bucket
	}
	p.mu.RUnlock()

	// Need to create new bucket
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if entry, exists := p.buckets[key]; exists {
		entry.lastUsed = time.Now()
		return entry.bucket
	}

	// Create new bucket
	bucket := NewTokenBucket(p.config.Capacity, p.config.Rate)
	p.buckets[key] = &tokenBucketEntry{
		bucket:   bucket,
		lastUsed: time.Now(),
	}

	return bucket
}

// Get retrieves an existing bucket.
//
// Parameters:
//   - key: Unique identifier for the bucket
//
// Returns:
//   - *TokenBucket: The token bucket if found, nil otherwise
func (p *TokenBucketPool) Get(key string) *TokenBucket {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if entry, exists := p.buckets[key]; exists {
		entry.lastUsed = time.Now()
		return entry.bucket
	}

	return nil
}

// Remove removes a bucket from the pool.
//
// Parameters:
//   - key: Unique identifier for the bucket
func (p *TokenBucketPool) Remove(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.buckets, key)
}

// Cleanup removes buckets that haven't been used for the specified duration.
//
// Parameters:
//   - maxIdle: Maximum idle duration
//
// Returns:
//   - int: Number of buckets removed
func (p *TokenBucketPool) Cleanup(maxIdle time.Duration) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, entry := range p.buckets {
		if now.Sub(entry.lastUsed) > maxIdle {
			delete(p.buckets, key)
			removed++
		}
	}

	return removed
}

// Size returns the number of buckets in the pool.
//
// Returns:
//   - int: Number of buckets
func (p *TokenBucketPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.buckets)
}

// Clear removes all buckets from the pool.
func (p *TokenBucketPool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buckets = make(map[string]*tokenBucketEntry)
}

// AllBuckets returns statistics for all buckets in the pool.
//
// Returns:
//   - map[string]TokenBucketStats: Statistics for each bucket
func (p *TokenBucketPool) AllBuckets() map[string]TokenBucketStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := make(map[string]TokenBucketStats, len(p.buckets))
	for key, entry := range p.buckets {
		stats[key] = entry.bucket.Stats()
	}

	return stats
}

//Personal.AI order the ending
