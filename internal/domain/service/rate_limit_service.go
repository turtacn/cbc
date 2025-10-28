// Package service 定义领域服务接口
// 限流服务接口 - 负责多维度限流控制（租户、设备、IP 等）
package service

import "time"

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	// Dimension 限流维度
	Dimension RateLimitDimension

	// Action 操作类型
	Action string

	// Limit 限流阈值（请求数）
	Limit int

	// Window 时间窗口（秒）
	Window int64

	// Algorithm 限流算法（token_bucket, sliding_window, fixed_window）
	Algorithm RateLimitAlgorithm

	// BurstSize 突发容量（仅 token_bucket 算法）
	BurstSize int

	// Enabled 是否启用
	Enabled bool
}

// RateLimitAlgorithm 限流算法枚举
type RateLimitAlgorithm string

const (
	// RateLimitAlgorithmTokenBucket 令牌桶算法
	RateLimitAlgorithmTokenBucket RateLimitAlgorithm = "token_bucket"

	// RateLimitAlgorithmSlidingWindow 滑动窗口算法
	RateLimitAlgorithmSlidingWindow RateLimitAlgorithm = "sliding_window"

	// RateLimitAlgorithmFixedWindow 固定窗口算法
	RateLimitAlgorithmFixedWindow RateLimitAlgorithm = "fixed_window"
)

// RateLimitServiceConfig 限流服务配置
type RateLimitServiceConfig struct {
	// GlobalLimits 全局限流配置
	GlobalLimits map[string]*RateLimitConfig

	// TenantLimits 租户级限流配置（默认）
	TenantLimits map[string]*RateLimitConfig

	// DeviceLimits 设备级限流配置（默认）
	DeviceLimits map[string]*RateLimitConfig

	// IPLimits IP 级限流配置（默认）
	IPLimits map[string]*RateLimitConfig

	// MgrLimits MGR 级限流配置（默认）
	MgrLimits map[string]*RateLimitConfig

	// EnableDistributedLock 是否启用分布式锁（防止并发冲突）
	EnableDistributedLock bool

	// RedisKeyPrefix Redis 键前缀
	RedisKeyPrefix string

	// CleanupInterval 清理过期数据的间隔（秒）
	CleanupInterval int64
}

// RateLimitStatus 限流状态
type RateLimitStatus struct {
	// Dimension 限流维度
	Dimension RateLimitDimension

	// Identifier 标识符
	Identifier string

	// Action 操作类型
	Action string

	// CurrentUsage 当前使用量
	CurrentUsage int

	// Limit 限流阈值
	Limit int

	// Remaining 剩余配额
	Remaining int

	// ResetAt 配额重置时间
	ResetAt time.Time

	// Allowed 是否允许请求
	Allowed bool
}

//Personal.AI order the ending
