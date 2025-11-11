// Package postgres provides a PostgreSQL implementation of the repository interfaces.
package postgres

import (
	"context"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"gorm.io/gorm"
)

// KeyRepository provides a PostgreSQL implementation of the repository.KeyRepository interface.
// It handles the persistence and retrieval of cryptographic keys.
// KeyRepository 提供了 repository.KeyRepository 接口的 PostgreSQL 实现。
// 它处理加密密钥的持久化和检索。
type KeyRepository struct {
	db *gorm.DB
}

// NewKeyRepository creates a new instance of the KeyRepository.
// NewKeyRepository 创建一个新的 KeyRepository 实例。
func NewKeyRepository(db *gorm.DB) repository.KeyRepository {
	return &KeyRepository{db: db}
}

// CreateKey persists a new cryptographic key to the database.
// CreateKey 将一个新的加密密钥持久化到数据库。
func (r *KeyRepository) CreateKey(ctx context.Context, key *models.Key) error {
	return r.db.WithContext(ctx).Create(key).Error
}

// GetKeyByKID retrieves a specific key for a given tenant using its Key ID (kid).
// Returns the key if found, otherwise an error (e.g., gorm.ErrRecordNotFound).
// GetKeyByKID 使用其密钥 ID (kid) 检索给定租户的特定密钥。
// 如果找到则返回密钥，否则返回错误（例如 gorm.ErrRecordNotFound）。
func (r *KeyRepository) GetKeyByKID(ctx context.Context, tenantID, kid string) (*models.Key, error) {
	var key models.Key
	err := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, kid).First(&key).Error
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// GetActiveKeys retrieves all keys with an 'active' status for a specific tenant.
// These are the keys currently used for signing tokens.
// GetActiveKeys 检索特定租户的所有状态为 'active' 的密钥。
// 这些是当前用于签署令牌的密钥。
func (r *KeyRepository) GetActiveKeys(ctx context.Context, tenantID string) ([]*models.Key, error) {
	var keys []*models.Key
	err := r.db.WithContext(ctx).Where("tenant_id = ? AND status = ?", tenantID, "active").Find(&keys).Error
	return keys, err
}

// GetDeprecatedKeys retrieves all keys with a 'deprecated' status for a specific tenant.
// These keys are no longer used for signing but can still be used for verification.
// GetDeprecatedKeys 检索特定租户的所有状态为 'deprecated' 的密钥。
// 这些密钥不再用于签名，但仍可用于验证。
func (r *KeyRepository) GetDeprecatedKeys(ctx context.Context, tenantID string) ([]*models.Key, error) {
	var keys []*models.Key
	err := r.db.WithContext(ctx).Where("tenant_id = ? AND status = ?", tenantID, "deprecated").Find(&keys).Error
	return keys, err
}

// UpdateKeyStatus changes the status of a specific key (e.g., from 'active' to 'deprecated').
// UpdateKeyStatus 更改特定密钥的状态（例如，从 'active' 更改为 'deprecated'）。
func (r *KeyRepository) UpdateKeyStatus(ctx context.Context, tenantID, kid, status string) error {
	return r.db.WithContext(ctx).Model(&models.Key{}).Where("tenant_id = ? AND id = ?", tenantID, kid).Update("status", status).Error
}
