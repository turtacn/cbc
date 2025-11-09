// Package postgres provides a PostgreSQL implementation of the repository interfaces.
package postgres

import (
	"context"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"gorm.io/gorm"
)

// KeyRepository is a PostgreSQL implementation of the KeyRepository interface.
type KeyRepository struct {
	db *gorm.DB
}

// NewKeyRepository creates a new KeyRepository.
func NewKeyRepository(db *gorm.DB) repository.KeyRepository {
	return &KeyRepository{db: db}
}

// CreateKey creates a new key in the database.
func (r *KeyRepository) CreateKey(ctx context.Context, key *models.Key) error {
	return r.db.WithContext(ctx).Create(key).Error
}

// GetKeyByKID retrieves a key by its KID.
func (r *KeyRepository) GetKeyByKID(ctx context.Context, tenantID, kid string) (*models.Key, error) {
	var key models.Key
	err := r.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, kid).First(&key).Error
	return &key, err
}

// GetActiveKeys retrieves all active keys for a tenant.
func (r *KeyRepository) GetActiveKeys(ctx context.Context, tenantID string) ([]*models.Key, error) {
	var keys []*models.Key
	err := r.db.WithContext(ctx).Where("tenant_id = ? AND status = ?", tenantID, "active").Find(&keys).Error
	return keys, err
}

// GetDeprecatedKeys retrieves all deprecated keys for a tenant.
func (r *KeyRepository) GetDeprecatedKeys(ctx context.Context, tenantID string) ([]*models.Key, error) {
	var keys []*models.Key
	err := r.db.WithContext(ctx).Where("tenant_id = ? AND status = ?", tenantID, "deprecated").Find(&keys).Error
	return keys, err
}

// UpdateKeyStatus updates the status of a key.
func (r *KeyRepository) UpdateKeyStatus(ctx context.Context, tenantID, kid, status string) error {
	return r.db.WithContext(ctx).Model(&models.Key{}).Where("tenant_id = ? AND id = ?", tenantID, kid).Update("status", status).Error
}
