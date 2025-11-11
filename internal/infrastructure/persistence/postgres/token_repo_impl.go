// Package postgres implements PostgreSQL-based token repository for multi-tenant management.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"gorm.io/gorm"
)

// TokenRepositoryImpl provides the PostgreSQL implementation of the TokenRepository interface.
// It handles the persistence, retrieval, and lifecycle management of JWTs.
// TokenRepositoryImpl 提供了 TokenRepository 接口的 PostgreSQL 实现。
// 它处理 JWT 的持久化、检索和生命周期管理。
type TokenRepositoryImpl struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewTokenRepository creates a new instance of the PostgreSQL-based token repository.
// NewTokenRepository 创建一个新的基于 PostgreSQL 的令牌仓库实例。
func NewTokenRepository(db *gorm.DB, log logger.Logger) repository.TokenRepository {
	return &TokenRepositoryImpl{
		db:     db,
		logger: log,
	}
}

// Save persists a new token record to the database.
// Save 将新的令牌记录持久化到数据库。
func (r *TokenRepositoryImpl) Save(ctx context.Context, token *models.Token) error {
	if err := r.db.WithContext(ctx).Create(token).Error; err != nil {
		r.logger.Error(ctx, "Failed to save token", err, logger.String("jti", token.JTI))
		return errors.ErrDatabaseOperation
	}
	return nil
}

// SaveBatch is not yet implemented.
// SaveBatch 尚未实现。
func (r *TokenRepositoryImpl) SaveBatch(ctx context.Context, tokens []*models.Token) error {
	return fmt.Errorf("not implemented")
}

// FindByJTI retrieves a single token from the database by its JTI (JWT ID).
// It returns a `TokenNotFound` error if no matching token is found.
// FindByJTI 通过其 JTI (JWT ID) 从数据库中检索单个令牌。
// 如果找不到匹配的令牌，则返回 `TokenNotFound` 错误。
func (r *TokenRepositoryImpl) FindByJTI(ctx context.Context, jti string) (*models.Token, error) {
	var token models.Token
	if err := r.db.WithContext(ctx).Where("jti = ?", jti).First(&token).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.ErrTokenNotFound(jti)
		}
		return nil, err
	}
	return &token, nil
}

// FindByAgentID is not yet implemented.
// FindByAgentID 尚未实现。
func (r *TokenRepositoryImpl) FindByAgentID(ctx context.Context, agentID string) ([]*models.Token, error) {
	return nil, fmt.Errorf("not implemented")
}

// FindByTenantID is not yet implemented.
// FindByTenantID 尚未实现。
func (r *TokenRepositoryImpl) FindByTenantID(ctx context.Context, tenantID string, limit, offset int) ([]*models.Token, int64, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

// FindActiveByAgentID is not yet implemented.
// FindActiveByAgentID 尚未实现。
func (r *TokenRepositoryImpl) FindActiveByAgentID(ctx context.Context, agentID string) ([]*models.Token, error) {
	return nil, fmt.Errorf("not implemented")
}

// Revoke marks a specific token as revoked in the database.
// It sets the `RevokedAt` timestamp and the reason for revocation.
// Revoke 将数据库中的特定令牌标记为已撤销。
// 它设置 `RevokedAt` 时间戳和撤销原因。
func (r *TokenRepositoryImpl) Revoke(ctx context.Context, jti string, reason string) error {
	result := r.db.WithContext(ctx).
		Model(&models.Token{}).
		Where("jti = ?", jti).
		Updates(map[string]interface{}{
			"revoked_at":      time.Now(),
			"revocation_reason": reason,
		})

	if result.Error != nil {
		r.logger.Error(ctx, "Failed to revoke token", result.Error, logger.String("jti", jti))
		return errors.ErrDatabaseOperation
	}
	if result.RowsAffected == 0 {
		return errors.ErrTokenNotFound(jti)
	}
	return nil
}

// RevokeByAgentID is not yet implemented.
// RevokeByAgentID 尚未实现。
func (r *TokenRepositoryImpl) RevokeByAgentID(ctx context.Context, agentID string, reason string) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

// RevokeByTenantID is not yet implemented.
// RevokeByTenantID 尚未实现。
func (r *TokenRepositoryImpl) RevokeByTenantID(ctx context.Context, tenantID string, reason string) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

// IsRevoked checks if a token has been marked as revoked.
// It returns true if the `RevokedAt` field is not NULL.
// IsRevoked 检查令牌是否已被标记为已撤销。
// 如果 `RevokedAt` 字段不为 NULL，则返回 true。
func (r *TokenRepositoryImpl) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Token{}).Where("jti = ? AND revoked_at IS NOT NULL", jti).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// DeleteExpired permanently removes expired tokens from the database.
// This is used for database cleanup to prevent it from growing indefinitely.
// DeleteExpired 从数据库中永久删除过期的令牌。
// 这用于数据库清理，以防止其无限增长。
func (r *TokenRepositoryImpl) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	result := r.db.WithContext(ctx).
		Where("expires_at < ?", before).
		Delete(&models.Token{})

	if result.Error != nil {
		r.logger.Error(ctx, "Failed to delete expired tokens", result.Error)
		return 0, errors.ErrDatabaseOperation
	}
	return result.RowsAffected, nil
}

// CountByTenantID is not yet implemented.
// CountByTenantID 尚未实现。
func (r *TokenRepositoryImpl) CountByTenantID(ctx context.Context, tenantID string) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

// CountActiveByTenantID counts the number of active (not expired, not revoked) tokens for a tenant.
// CountActiveByTenantID 统计租户的活动（未过期、未撤销）令牌数量。
func (r *TokenRepositoryImpl) CountActiveByTenantID(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Token{}).Where("tenant_id = ? AND expires_at > ? AND revoked_at IS NULL", tenantID, time.Now()).Count(&count).Error
	return count, err
}

// UpdateLastUsedAt is not yet implemented.
// UpdateLastUsedAt 尚未实现。
func (r *TokenRepositoryImpl) UpdateLastUsedAt(ctx context.Context, jti string, lastUsedAt time.Time) error {
	return fmt.Errorf("not implemented")
}
