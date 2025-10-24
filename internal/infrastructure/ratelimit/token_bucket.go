package ratelimit

import (
	"sync"
	"time"

	"github.com/turtacn/cbc/pkg/constants"
)

// TokenBucket implements a thread-safe token bucket rate limiter.
type TokenBucket struct {
	mu         sync.Mutex
	rate       float64 // tokens per second
	capacity   float64
	tokens     float64
	lastUpdate time.Time
}

// NewTokenBucket creates a new TokenBucket.
func NewTokenBucket(rate, capacity float64) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		capacity:   capacity,
		tokens:     capacity,
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request is allowed and consumes one token.
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1)
}

// AllowN checks if n tokens can be consumed.
func (tb *TokenBucket) AllowN(n float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}

	return false
}

// refill calculates and adds new tokens to the bucket.
func (tb *TokenBucket) refill() {
	now := time.Now()
	duration := now.Sub(tb.lastUpdate)
	tokensToAdd := duration.Seconds() * tb.rate

	tb.tokens = tb.tokens + tokensToAdd
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastUpdate = now
}
//Personal.AI order the ending