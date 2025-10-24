// Package repository 定义领域仓储接口
// 仓储接口遵循 DDD 原则，定义领域对象的持久化契约
package repository

import (
	"context"
	"time"

	"github.com/turtacn/cbc/internal/domain/models"
)

// TokenRepository 定义令牌仓储接口
// 该接口定义了令牌领域对象的持久化操作契约
// 实现类：internal/infrastructure/persistence/postgres/token_repo_impl.go
type TokenRepository interface {
	// Save 保存令牌元数据到持久化存储
	// 参数：
	//   - ctx: 请求上下文，用于超时控制和链路追踪
	//   - token: 令牌领域模型
	// 返回：
	//   - error: 保存失败时返回错误（如主键冲突、数据库连接失败等）
	Save(ctx context.Context, token *models.Token) error

	// SaveBatch 批量保存令牌元数据
	// 用于性能优化场景（如批量设备注册）
	// 参数：
	//   - ctx: 请求上下文
	//   - tokens: 令牌领域模型切片
	// 返回：
	//   - error: 任意一个令牌保存失败时返回错误
	SaveBatch(ctx context.Context, tokens []*models.Token) error

	// FindByJTI 根据 JWT 唯一标识符（JTI）查询令牌
	// 参数：
	//   - ctx: 请求上下文
	//   - jti: JWT 唯一标识符
	// 返回：
	//   - *models.Token: 查询到的令牌对象
	//   - error: 查询失败或令牌不存在时返回错误（ErrTokenNotFound）
	FindByJTI(ctx context.Context, jti string) (*models.Token, error)

	// FindByAgentID 根据 Agent ID 查询所有令牌
	// 用于管理端查询设备的所有活跃令牌
	// 参数：
	//   - ctx: 请求上下文
	//   - agentID: 终端 Agent 唯一标识符
	// 返回：
	//   - []*models.Token: 令牌切片（按创建时间倒序）
	//   - error: 查询失败时返回错误
	FindByAgentID(ctx context.Context, agentID string) ([]*models.Token, error)

	// FindByTenantID 根据租户 ID 查询令牌（分页）
	// 用于租户级别的令牌管理和审计
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - limit: 每页数量
	//   - offset: 偏移量
	// 返回：
	//   - []*models.Token: 令牌切片
	//   - int64: 总记录数
	//   - error: 查询失败时返回错误
	FindByTenantID(ctx context.Context, tenantID string, limit, offset int) ([]*models.Token, int64, error)

	// FindActiveByAgentID 根据 Agent ID 查询所有未过期且未吊销的令牌
	// 用于设备重新注册时的凭证冲突检测
	// 参数：
	//   - ctx: 请求上下文
	//   - agentID: 终端 Agent 唯一标识符
	// 返回：
	//   - []*models.Token: 活跃令牌切片
	//   - error: 查询失败时返回错误
	FindActiveByAgentID(ctx context.Context, agentID string) ([]*models.Token, error)

	// Revoke 吊销指定令牌
	// 该操作会更新令牌的 RevokedAt 字段
	// 参数：
	//   - ctx: 请求上下文
	//   - jti: JWT 唯一标识符
	//   - reason: 吊销原因（如 "admin_revoked", "security_incident"）
	// 返回：
	//   - error: 吊销失败时返回错误（令牌不存在或已吊销）
	Revoke(ctx context.Context, jti string, reason string) error

	// RevokeByAgentID 吊销指定 Agent 的所有活跃令牌
	// 用于设备安全事件响应（如设备丢失、密钥泄露）
	// 参数：
	//   - ctx: 请求上下文
	//   - agentID: 终端 Agent 唯一标识符
	//   - reason: 吊销原因
	// 返回：
	//   - int64: 吊销的令牌数量
	//   - error: 吊销失败时返回错误
	RevokeByAgentID(ctx context.Context, agentID string, reason string) (int64, error)

	// RevokeByTenantID 吊销指定租户的所有活跃令牌
	// 用于租户级别的安全事件响应（如密钥泄露、紧急封禁）
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - reason: 吊销原因
	// 返回：
	//   - int64: 吊销的令牌数量
	//   - error: 吊销失败时返回错误
	RevokeByTenantID(ctx context.Context, tenantID string, reason string) (int64, error)

	// IsRevoked 检查令牌是否已被吊销
	// 该方法应优先从缓存（Redis）查询，缓存未命中时再查询数据库
	// 参数：
	//   - ctx: 请求上下文
	//   - jti: JWT 唯一标识符
	// 返回：
	//   - bool: true 表示已吊销，false 表示未吊销或不存在
	//   - error: 查询失败时返回错误
	IsRevoked(ctx context.Context, jti string) (bool, error)

	// DeleteExpired 删除已过期的令牌元数据
	// 该方法用于定期清理历史数据，减少数据库存储压力
	// 参数：
	//   - ctx: 请求上下文
	//   - before: 删除此时间点之前过期的令牌
	// 返回：
	//   - int64: 删除的令牌数量
	//   - error: 删除失败时返回错误
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)

	// CountByTenantID 统计租户的令牌总数
	// 用于租户级别的使用量统计和配额管理
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	// 返回：
	//   - int64: 令牌总数
	//   - error: 统计失败时返回错误
	CountByTenantID(ctx context.Context, tenantID string) (int64, error)

	// CountActiveByTenantID 统计租户的活跃令牌数
	// 用于实时监控租户的在线设备数量
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	// 返回：
	//   - int64: 活跃令牌数
	//   - error: 统计失败时返回错误
	CountActiveByTenantID(ctx context.Context, tenantID string) (int64, error)

	// UpdateLastUsedAt 更新令牌的最后使用时间
	// 用于令牌活跃度追踪和空闲令牌清理
	// 参数：
	//   - ctx: 请求上下文
	//   - jti: JWT 唯一标识符
	//   - lastUsedAt: 最后使用时间
	// 返回：
	//   - error: 更新失败时返回错误
	UpdateLastUsedAt(ctx context.Context, jti string, lastUsedAt time.Time) error
}

// TokenMetadataQuery 令牌元数据查询参数
// 用于复杂查询场景（如管理端的令牌列表筛选）
type TokenMetadataQuery struct {
	TenantID      string           // 租户 ID（可选）
	AgentID       string           // Agent ID（可选）
	TokenType     models.TokenType // 令牌类型（可选）
	Status        string           // 状态：active, revoked, expired（可选）
	IssuedAfter   *time.Time       // 颁发时间下界（可选）
	IssuedBefore  *time.Time       // 颁发时间上界（可选）
	ExpiresAfter  *time.Time       // 过期时间下界（可选）
	ExpiresBefore *time.Time       // 过期时间上界（可选）
	Limit         int              // 每页数量（默认 100，最大 1000）
	Offset        int              // 偏移量
	OrderBy       string           // 排序字段（如 "created_at DESC"）
}

// FindByQuery 根据查询条件查询令牌（高级查询接口）
// 该方法用于管理端的复杂查询场景
// 参数：
//   - ctx: 请求上下文
//   - query: 查询参数
//
// 返回：
//   - []*models.Token: 令牌切片
//   - int64: 总记录数
//   - error: 查询失败时返回错误
//
// FindByQuery(ctx context.Context, query TokenMetadataQuery) ([]*models.Token, int64, error)

//Personal.AI order the ending
