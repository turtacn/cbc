// Package service 定义领域服务接口
// 限流服务接口 - 负责多维度限流控制（租户、设备、IP 等）
package service

import (
	"context"
	"time"
)

// RateLimitService 限流服务接口
// 提供多维度限流功能，支持令牌桶、滑动窗口等算法
type RateLimitService interface {
	// Allow 检查是否允许请求
	// 基于指定维度和限流策略判断是否允许当前请求通过
	// 参数:
	//   ctx: 上下文对象
	//   dimension: 限流维度（tenant、device、ip、global）
	//   identifier: 标识符（如租户 ID、设备 ID、IP 地址）
	//   action: 操作类型（如 token_issue、device_register）
	// 返回:
	//   allowed: 是否允许请求
	//   remaining: 剩余配额
	//   resetAt: 配额重置时间
	//   error: 错误信息
	Allow(
		ctx context.Context,
		dimension RateLimitDimension,
		identifier string,
		action string,
	) (allowed bool, remaining int, resetAt time.Time, err error)

	// AllowN 批量检查是否允许 N 个请求
	// 用于批量操作的限流检查
	// 参数:
	//   ctx: 上下文对象
	//   dimension: 限流维度
	//   identifier: 标识符
	//   action: 操作类型
	//   n: 请求数量
	// 返回:
	//   allowed: 是否允许请求
	//   remaining: 剩余配额
	//   resetAt: 配额重置时间
	//   error: 错误信息
	AllowN(
		ctx context.Context,
		dimension RateLimitDimension,
		identifier string,
		action string,
		n int,
	) (allowed bool, remaining int, resetAt time.Time, err error)

	// ResetLimit 重置限流计数器
	// 清除指定维度和标识符的限流记录
	// 参数:
	//   ctx: 上下文对象
	//   dimension: 限流维度
	//   identifier: 标识符
	//   action: 操作类型（可选，留空则重置所有操作）
	// 返回:
	//   error: 错误信息
	ResetLimit(
		ctx context.Context,
		dimension RateLimitDimension,
		identifier string,
		action string,
	) error

	// GetCurrentUsage 获取当前使用量
	// 查询指定维度和标识符的当前限流使用情况
	// 参数:
	//   ctx: 上下文对象
	//   dimension: 限流维度
	//   identifier: 标识符
	//   action: 操作类型
	// 返回:
	//   usage: 当前使用量
	//   limit: 限流阈值
	//   resetAt: 配额重置时间
	//   error: 错误信息
	GetCurrentUsage(
		ctx context.Context,
		dimension RateLimitDimension,
		identifier string,
		action string,
	) (usage int, limit int, resetAt time.Time, err error)

	// SetCustomLimit 设置自定义限流阈值
	// 为特定租户或设备设置临时限流策略
	// 参数:
	//   ctx: 上下文对象
	//   dimension: 限流维度
	//   identifier: 标识符
	//   action: 操作类型
	//   limit: 限流阈值
	//   window: 时间窗口（秒）
	//   ttl: 自定义限流的有效期（秒）
	// 返回:
	//   error: 错误信息
	SetCustomLimit(
		ctx context.Context,
		dimension RateLimitDimension,
		identifier string,
		action string,
		limit int,
		window int64,
		ttl int64,
	) error

	// GetLimitConfig 获取限流配置
	// 查询指定维度和操作的限流策略配置
	// 参数:
	//   ctx: 上下文对象
	//   dimension: 限流维度
	//   action: 操作类型
	// 返回:
	//   config: 限流配置
	//   error: 错误信息
	GetLimitConfig(
		ctx context.Context,
		dimension RateLimitDimension,
		action string,
	) (*RateLimitConfig, error)

	// IncrementCounter 手动增加计数器
	// 用于特定场景下的手动限流计数
	// 参数:
	//   ctx: 上下文对象
	//   dimension: 限流维度
	//   identifier: 标识符
	//   action: 操作类型
	//   increment: 增量
	// 返回:
	//   newCount: 新的计数值
	//   error: 错误信息
	IncrementCounter(
		ctx context.Context,
		dimension RateLimitDimension,
		identifier string,
		action string,
		increment int,
	) (int, error)

	// DecayCounter 衰减计数器（滑动窗口）
	// 移除过期的计数记录，实现滑动窗口效果
	// 参数:
	//   ctx: 上下文对象
	//   dimension: 限流维度
	//   identifier: 标识符
	//   action: 操作类型
	// 返回:
	//   error: 错误信息
	DecayCounter(
		ctx context.Context,
		dimension RateLimitDimension,
		identifier string,
		action string,
	) error
}

// RateLimitDimension 限流维度枚举
type RateLimitDimension string

const (
	// RateLimitDimensionGlobal 全局限流
	RateLimitDimensionGlobal RateLimitDimension = "global"

	// RateLimitDimensionTenant 租户级限流
	RateLimitDimensionTenant RateLimitDimension = "tenant"

	// RateLimitDimensionDevice 设备级限流
	RateLimitDimensionDevice RateLimitDimension = "device"

	// RateLimitDimensionIP IP 级限流
	RateLimitDimensionIP RateLimitDimension = "ip"

	// RateLimitDimensionMgr MGR 级限流
	RateLimitDimensionMgr RateLimitDimension = "mgr"
)

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
