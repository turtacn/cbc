// Package service 定义领域服务接口
// 限流服务接口 - 负责多维度限流控制（租户、设备、IP 等）
package service

import "time"

// RateLimitConfig defines the parameters for a single rate limit rule.
// RateLimitConfig 限流配置。
type RateLimitConfig struct {
	// Dimension is the dimension to which the limit applies (e.g., "tenant", "device").
	// Dimension 限流维度。
	Dimension RateLimitDimension

	// Action is the specific operation being limited (e.g., "login", "register").
	// Action 操作类型。
	Action string

	// Limit is the maximum number of requests allowed within the time window.
	// Limit 限流阈值（请求数）。
	Limit int

	// Window is the duration of the time window in seconds.
	// Window 时间窗口（秒）。
	Window int64

	// Algorithm is the rate limiting algorithm to use.
	// Algorithm 限流算法（token_bucket, sliding_window, fixed_window）。
	Algorithm RateLimitAlgorithm

	// BurstSize is the maximum number of requests allowed in a burst (for token bucket algorithm).
	// BurstSize 突发容量（仅 token_bucket 算法）。
	BurstSize int

	// Enabled indicates whether this rate limit rule is active.
	// Enabled 是否启用。
	Enabled bool
}

// RateLimitAlgorithm is an enumeration of supported rate limiting algorithms.
// RateLimitAlgorithm 限流算法枚举。
type RateLimitAlgorithm string

const (
	// RateLimitAlgorithmTokenBucket represents the token bucket algorithm.
	// RateLimitAlgorithmTokenBucket 令牌桶算法。
	RateLimitAlgorithmTokenBucket RateLimitAlgorithm = "token_bucket"

	// RateLimitAlgorithmSlidingWindow represents the sliding window algorithm.
	// RateLimitAlgorithmSlidingWindow 滑动窗口算法。
	RateLimitAlgorithmSlidingWindow RateLimitAlgorithm = "sliding_window"

	// RateLimitAlgorithmFixedWindow represents the fixed window algorithm.
	// RateLimitAlgorithmFixedWindow 固定窗口算法。
	RateLimitAlgorithmFixedWindow RateLimitAlgorithm = "fixed_window"
)

// RateLimitServiceConfig holds the overall configuration for the rate limiting service.
// RateLimitServiceConfig 限流服务配置。
type RateLimitServiceConfig struct {
	// GlobalLimits defines the system-wide rate limit rules.
	// GlobalLimits 全局限流配置。
	GlobalLimits map[string]*RateLimitConfig

	// TenantLimits defines the default rate limit rules for tenants.
	// TenantLimits 租户级限流配置（默认）。
	TenantLimits map[string]*RateLimitConfig

	// DeviceLimits defines the default rate limit rules for devices.
	// DeviceLimits 设备级限流配置（默认）。
	DeviceLimits map[string]*RateLimitConfig

	// IPLimits defines the default rate limit rules for IP addresses.
	// IPLimits IP 级限流配置（默认）。
	IPLimits map[string]*RateLimitConfig

	// MgrLimits defines the default rate limit rules for MGR clients.
	// MgrLimits MGR 级限流配置（默认）。
	MgrLimits map[string]*RateLimitConfig

	// EnableDistributedLock enables a distributed lock to prevent race conditions in clustered environments.
	// EnableDistributedLock 是否启用分布式锁（防止并发冲突）。
	EnableDistributedLock bool

	// RedisKeyPrefix is the prefix for all keys stored in Redis for rate limiting.
	// RedisKeyPrefix Redis 键前缀。
	RedisKeyPrefix string

	// CleanupInterval is the interval in seconds for cleaning up expired rate limit data.
	// CleanupInterval 清理过期数据的间隔（秒）。
	CleanupInterval int64
}

// RateLimitStatus represents the current state of a rate limit for a specific identifier.
// RateLimitStatus 限流状态。
type RateLimitStatus struct {
	// Dimension is the dimension to which the limit applies.
	// Dimension 限流维度。
	Dimension RateLimitDimension

	// Identifier is the unique identifier being tracked (e.g., a tenant ID or IP address).
	// Identifier 标识符。
	Identifier string

	// Action is the specific operation being limited.
	// Action 操作类型。
	Action string

	// CurrentUsage is the number of requests consumed in the current window.
	// CurrentUsage 当前使用量。
	CurrentUsage int

	// Limit is the maximum number of requests allowed.
	// Limit 限流阈值。
	Limit int

	// Remaining is the number of requests remaining in the current window.
	// Remaining 剩余配额。
	Remaining int

	// ResetAt is the time when the rate limit window will reset.
	// ResetAt 配额重置时间。
	ResetAt time.Time

	// Allowed indicates whether the latest request was allowed.
	// Allowed 是否允许请求。
	Allowed bool
}

//Personal.AI order the ending
