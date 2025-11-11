// Package repository 定义领域仓储接口
// 仓储接口遵循 DDD 原则，定义领域对象的持久化契约
package repository

import (
	"context"
	"time"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/constants"
)

// TokenRepository defines the contract for persistence operations related to the Token domain object.
// The implementation can be found at: internal/infrastructure/persistence/postgres/token_repo_impl.go
// TokenRepository 定义了令牌领域对象的持久化操作契约。
// 实现类位于：internal/infrastructure/persistence/postgres/token_repo_impl.go
type TokenRepository interface {
	// Save persists a token's metadata to the data store.
	// Save 保存令牌元数据到持久化存储。
	Save(ctx context.Context, token *models.Token) error

	// SaveBatch persists multiple tokens in a single operation.
	// Used for performance optimization in scenarios like bulk device registration.
	// SaveBatch 批量保存令牌元数据。用于性能优化场景（如批量设备注册）。
	SaveBatch(ctx context.Context, tokens []*models.Token) error

	// FindByJTI retrieves a token by its unique JWT ID (JTI).
	// FindByJTI 根据 JWT 唯一标识符（JTI）查询令牌。
	FindByJTI(ctx context.Context, jti string) (*models.Token, error)

	// FindByAgentID retrieves all tokens associated with a specific Agent ID.
	// Used for administrative purposes to query all active tokens for a device.
	// FindByAgentID 根据 Agent ID 查询所有令牌。用于管理端查询设备的所有活跃令牌。
	FindByAgentID(ctx context.Context, agentID string) ([]*models.Token, error)

	// FindByTenantID retrieves a paginated list of tokens for a specific tenant.
	// Used for tenant-level token management and auditing.
	// FindByTenantID 根据租户 ID 查询令牌（分页）。用于租户级别的令牌管理和审计。
	FindByTenantID(ctx context.Context, tenantID string, limit, offset int) ([]*models.Token, int64, error)

	// FindActiveByAgentID retrieves all non-expired and non-revoked tokens for an Agent ID.
	// Used for credential conflict detection during device re-registration.
	// FindActiveByAgentID 根据 Agent ID 查询所有未过期且未吊销的令牌。用于设备重新注册时的凭证冲突检测。
	FindActiveByAgentID(ctx context.Context, agentID string) ([]*models.Token, error)

	// Revoke invalidates a specific token by its JTI.
	// This operation updates the token's RevokedAt field.
	// Revoke 吊销指定令牌。该操作会更新令牌的 RevokedAt 字段。
	Revoke(ctx context.Context, jti string, reason string) error

	// RevokeByAgentID revokes all active tokens for a specific Agent ID.
	// Used for security incident response (e.g., device loss, key compromise).
	// RevokeByAgentID 吊销指定 Agent 的所有活跃令牌。用于设备安全事件响应（如设备丢失、密钥泄露）。
	RevokeByAgentID(ctx context.Context, agentID string, reason string) (int64, error)

	// RevokeByTenantID revokes all active tokens for a specific tenant.
	// Used for tenant-level security incident response.
	// RevokeByTenantID 吊销指定租户的所有活跃令牌。用于租户级别的安全事件响应（如密钥泄露、紧急封禁）。
	RevokeByTenantID(ctx context.Context, tenantID string, reason string) (int64, error)

	// IsRevoked checks if a token has been revoked.
	// This should prioritize checking a cache (like Redis) before hitting the database.
	// IsRevoked 检查令牌是否已被吊销。该方法应优先从缓存（Redis）查询，缓存未命中时再查询数据库。
	IsRevoked(ctx context.Context, jti string) (bool, error)

	// DeleteExpired removes expired token metadata from the data store.
	// Used for periodic cleanup to reduce database storage.
	// DeleteExpired 删除已过期的令牌元数据。该方法用于定期清理历史数据，减少数据库存储压力。
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)

	// CountByTenantID counts the total number of tokens for a tenant.
	// Used for usage statistics and quota management.
	// CountByTenantID 统计租户的令牌总数。用于租户级别的使用量统计和配额管理。
	CountByTenantID(ctx context.Context, tenantID string) (int64, error)

	// CountActiveByTenantID counts the number of active tokens for a tenant.
	// Used for real-time monitoring of online devices.
	// CountActiveByTenantID 统计租户的活跃令牌数。用于实时监控租户的在线设备数量。
	CountActiveByTenantID(ctx context.Context, tenantID string) (int64, error)

	// UpdateLastUsedAt updates the last used timestamp for a token.
	// Used for tracking token activity and cleaning up idle tokens.
	// UpdateLastUsedAt 更新令牌的最后使用时间。用于令牌活跃度追踪和空闲令牌清理。
	UpdateLastUsedAt(ctx context.Context, jti string, lastUsedAt time.Time) error
}

// TokenMetadataQuery defines parameters for complex token metadata searches.
// Used for filtering and sorting in administrative interfaces.
// TokenMetadataQuery 令牌元数据查询参数。用于复杂查询场景（如管理端的令牌列表筛选）。
type TokenMetadataQuery struct {
	// TenantID filters by tenant ID (optional).
	// TenantID 按租户 ID 筛选（可选）。
	TenantID      string              // 租户 ID（可选）
	// AgentID filters by Agent ID (optional).
	// AgentID 按 Agent ID 筛选（可选）。
	AgentID       string              // Agent ID（可选）
	// TokenType filters by token type (optional).
	// TokenType 按令牌类型筛选（可选）。
	TokenType     constants.TokenType // 令牌类型（可选）
	// Status filters by token status: active, revoked, expired (optional).
	// Status 按令牌状态筛选：active、revoked、expired（可选）。
	Status        string              // 状态：active, revoked, expired（可选）
	// IssuedAfter filters for tokens issued after this time (optional).
	// IssuedAfter 筛选在此时间之后颁发的令牌（可选）。
	IssuedAfter   *time.Time          // 颁发时间下界（可选）
	// IssuedBefore filters for tokens issued before this time (optional).
	// IssuedBefore 筛选在此时间之前颁发的令牌（可选）。
	IssuedBefore  *time.Time          // 颁发时间上界（可选）
	// ExpiresAfter filters for tokens that expire after this time (optional).
	// ExpiresAfter 筛选在此时间之后过期的令牌（可选）。
	ExpiresAfter  *time.Time       // 过期时间下界（可选）
	// ExpiresBefore filters for tokens that expire before this time (optional).
	// ExpiresBefore 筛选在此时间之前过期的令牌（可选）。
	ExpiresBefore *time.Time       // 过期时间上界（可选）
	// Limit specifies the number of results per page (default 100, max 1000).
	// Limit 指定每页的结果数（默认 100，最大 1000）。
	Limit         int              // 每页数量（默认 100，最大 1000）
	// Offset specifies the number of results to skip.
	// Offset 指定要跳过的结果数。
	Offset        int              // 偏移量
	// OrderBy specifies the sort order (e.g., "created_at DESC").
	// OrderBy 指定排序顺序（例如，“created_at DESC”）。
	OrderBy       string           // 排序字段（如 "created_at DESC"）
}

// FindByQuery is an advanced search method for tenants based on a query object.
// This method is intended for complex filtering scenarios in administrative UIs.
// FindByQuery 根据查询条件查询租户（高级查询接口）。该方法用于管理端的复杂查询场景。
//
// FindByQuery(ctx context.Context, query TokenMetadataQuery) ([]*models.Token, int64, error)
