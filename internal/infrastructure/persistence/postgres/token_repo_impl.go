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

// TokenRepositoryImpl implements TokenRepository interface using PostgreSQL.
type TokenRepositoryImpl struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewTokenRepository creates a new PostgreSQL token repository instance.
func NewTokenRepository(db *gorm.DB, log logger.Logger) repository.TokenRepository {
	return &TokenRepositoryImpl{
		db:     db,
		logger: log,
	}
}

func (r *TokenRepositoryImpl) Save(ctx context.Context, token *models.Token) error {
	if err := r.db.WithContext(ctx).Create(token).Error; err != nil {
		r.logger.Error(ctx, "Failed to save token", err, logger.String("jti", token.JTI))
		return errors.ErrDatabaseOperation
	}
	return nil
}

func (r *TokenRepositoryImpl) SaveBatch(ctx context.Context, tokens []*models.Token) error {
	return fmt.Errorf("not implemented")
}

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

func (r *TokenRepositoryImpl) FindByAgentID(ctx context.Context, agentID string) ([]*models.Token, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *TokenRepositoryImpl) FindByTenantID(ctx context.Context, tenantID string, limit, offset int) ([]*models.Token, int64, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

func (r *TokenRepositoryImpl) FindActiveByAgentID(ctx context.Context, agentID string) ([]*models.Token, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *TokenRepositoryImpl) Revoke(ctx context.Context, jti string, reason string) error {
	return fmt.Errorf("not implemented")
}

func (r *TokenRepositoryImpl) RevokeByAgentID(ctx context.Context, agentID string, reason string) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

func (r *TokenRepositoryImpl) RevokeByTenantID(ctx context.Context, tenantID string, reason string) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

func (r *TokenRepositoryImpl) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Token{}).Where("jti = ? AND revoked_at IS NOT NULL", jti).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *TokenRepositoryImpl) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

func (r *TokenRepositoryImpl) CountByTenantID(ctx context.Context, tenantID string) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

func (r *TokenRepositoryImpl) CountActiveByTenantID(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Token{}).Where("tenant_id = ? AND expires_at > ? AND revoked_at IS NULL", tenantID, time.Now()).Count(&count).Error
	return count, err
}

func (r *TokenRepositoryImpl) UpdateLastUsedAt(ctx context.Context, jti string, lastUsedAt time.Time) error {
	return fmt.Errorf("not implemented")
}
