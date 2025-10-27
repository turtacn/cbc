// Package postgres implements PostgreSQL-based tenant repository for multi-tenant management.
// It provides tenant lifecycle management, quota enforcement, and tenant isolation.
package postgres

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// TenantRepoImpl implements TenantRepository interface using PostgreSQL.
type TenantRepoImpl struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewTenantRepository creates a new PostgreSQL-based tenant repository instance.
func NewTenantRepository(db *gorm.DB, log logger.Logger) repository.TenantRepository {
	return &TenantRepoImpl{
		db:     db,
		logger: log,
	}
}

// Save creates a new tenant in the system.
func (r *TenantRepoImpl) Save(ctx context.Context, tenant *models.Tenant) error {
	startTime := time.Now()

	// Set creation timestamp
	now := time.Now()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now

	// Set default status if not specified
	if tenant.Status == "" {
		tenant.Status = constants.TenantStatusActive
	}

	// Create tenant record
	if err := r.db.WithContext(ctx).Create(tenant).Error; err != nil {
		r.logger.Error(ctx, "Failed to create tenant", err,
			logger.String("tenant_name", tenant.TenantName),
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	latency := time.Since(startTime)
	r.logger.Info(ctx, "Tenant created successfully",
		logger.String("tenant_id", tenant.TenantID),
		logger.String("tenant_name", tenant.TenantName),
		logger.String("status", string(tenant.Status)),
		logger.Int64("latency_ms", latency.Milliseconds()),
	)

	return nil
}

// Update modifies an existing tenant record.
func (r *TenantRepoImpl) Update(ctx context.Context, tenant *models.Tenant) error {
	tenant.UpdatedAt = time.Now()

	result := r.db.WithContext(ctx).
		Model(tenant).
		Where("tenant_id = ?", tenant.TenantID).
		Updates(tenant)

	if result.Error != nil {
		r.logger.Error(ctx, "Failed to update tenant", result.Error,
			logger.String("tenant_id", tenant.TenantID),
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Warn(ctx, "Tenant not found for update", logger.String("tenant_id", tenant.TenantID))
		return errors.ErrTenantNotFound(tenant.TenantID)
	}

	r.logger.Info(ctx, "Tenant updated successfully",
		logger.String("tenant_id", tenant.TenantID),
	)

	return nil
}

// FindByID retrieves a tenant by its unique identifier.
func (r *TenantRepoImpl) FindByID(ctx context.Context, tenantID string) (*models.Tenant, error) {
	var tenant models.Tenant

	err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		First(&tenant).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Debug(ctx, "Tenant not found", logger.String("tenant_id", tenantID))
			return nil, errors.ErrTenantNotFound(tenantID)
		}
		r.logger.Error(ctx, "Failed to retrieve tenant by ID", err,
			logger.String("tenant_id", tenantID),
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	return &tenant, nil
}

func (r *TenantRepoImpl) FindByName(ctx context.Context, name string) (*models.Tenant, error) {
	var tenant models.Tenant
	err := r.db.WithContext(ctx).Where("tenant_name = ?", name).First(&tenant).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.ErrTenantNotFound(name)
		}
		return nil, err
	}
	return &tenant, nil
}

func (r *TenantRepoImpl) FindAll(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

// FindActiveAll retrieves all active tenants.
func (r *TenantRepoImpl) FindActiveAll(ctx context.Context) ([]*models.Tenant, error) {
	var tenants []*models.Tenant
	err := r.db.WithContext(ctx).Where("status = ?", constants.TenantStatusActive).Find(&tenants).Error
	if err != nil {
		r.logger.Error(ctx, "Failed to retrieve active tenants", err)
		return nil, err
	}
	return tenants, nil
}

// Exists checks if a tenant exists by ID.
func (r *TenantRepoImpl) Exists(ctx context.Context, tenantID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Tenant{}).Where("tenant_id = ?", tenantID).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// UpdateStatus changes tenant status (active, suspended, deleted).
func (r *TenantRepoImpl) UpdateStatus(ctx context.Context, tenantID string, status constants.TenantStatus) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&models.Tenant{}).
		Where("tenant_id = ?", tenantID).
		Updates(map[string]interface{}{
			"status":     status,
			"updated_at": now,
		})

	if result.Error != nil {
		r.logger.Error(ctx, "Failed to update tenant status", result.Error,
			logger.String("tenant_id", tenantID),
			logger.String("status", string(status)),
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return errors.ErrTenantNotFound(tenantID)
	}

	r.logger.Info(ctx, "Tenant status updated",
		logger.String("tenant_id", tenantID),
		logger.String("status", string(status)),
	)

	return nil
}

func (r *TenantRepoImpl) UpdateRateLimitConfig(ctx context.Context, tenantID string, config *models.RateLimitConfig) error {
	return fmt.Errorf("not implemented")
}

func (r *TenantRepoImpl) UpdateTokenTTLConfig(ctx context.Context, tenantID string, config *models.TokenTTLConfig) error {
	return fmt.Errorf("not implemented")
}

func (r *TenantRepoImpl) UpdateKeyRotationPolicy(ctx context.Context, tenantID string, policy *models.KeyRotationPolicy) error {
	return fmt.Errorf("not implemented")
}

// Delete removes a tenant record from the system.
func (r *TenantRepoImpl) Delete(ctx context.Context, tenantID string) error {
	result := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Delete(&models.Tenant{})

	if result.Error != nil {
		r.logger.Error(ctx, "Failed to delete tenant", result.Error,
			logger.String("tenant_id", tenantID),
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Debug(ctx, "Tenant not found for deletion", logger.String("tenant_id", tenantID))
		return errors.ErrTenantNotFound(tenantID)
	}

	r.logger.Info(ctx, "Tenant deleted successfully", logger.String("tenant_id", tenantID))
	return nil
}

func (r *TenantRepoImpl) GetTenantMetrics(ctx context.Context, tenantID string) (*repository.TenantMetrics, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *TenantRepoImpl) GetAllMetrics(ctx context.Context) (*repository.SystemMetrics, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *TenantRepoImpl) IncrementRequestCount(ctx context.Context, tenantID string, count int64) error {
	return fmt.Errorf("not implemented")
}

func (r *TenantRepoImpl) UpdateLastActivityAt(ctx context.Context, tenantID string, lastActivityAt time.Time) error {
	return fmt.Errorf("not implemented")
}
