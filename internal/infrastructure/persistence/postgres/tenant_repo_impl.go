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

// TenantRepoImpl provides the PostgreSQL implementation for the TenantRepository interface.
// It manages the persistence and retrieval of tenant data.
// TenantRepoImpl 提供了 TenantRepository 接口的 PostgreSQL 实现。
// 它管理租户数据的持久化和检索。
type TenantRepoImpl struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewTenantRepository creates a new instance of the PostgreSQL-based tenant repository.
// NewTenantRepository 创建一个新的基于 PostgreSQL 的租户仓库实例。
func NewTenantRepository(db *gorm.DB, log logger.Logger) repository.TenantRepository {
	return &TenantRepoImpl{
		db:     db,
		logger: log,
	}
}

// Save persists a new tenant record to the database.
// It sets timestamps and a default status if one is not provided.
// Save 将新的租户记录持久化到数据库。
// 如果未提供状态，它会设置时间戳和默认状态。
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

// Update modifies an existing tenant's details in the database.
// It automatically updates the `UpdatedAt` timestamp.
// Update 修改数据库中现有租户的详细信息。
// 它会自动更新 `UpdatedAt` 时间戳。
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

// FindByID retrieves a single tenant from the database by their unique ID.
// Returns a `TenantNotFound` error if no tenant is found.
// FindByID 通过其唯一 ID 从数据库中检索单个租户。
// 如果找不到租户，则返回 `TenantNotFound` 错误。
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

// FindByName retrieves a single tenant from the database by their name.
// Returns a `TenantNotFound` error if no tenant is found.
// FindByName 通过名称从数据库中检索单个租户。
// 如果找不到租户，则返回 `TenantNotFound` 错误。
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

// FindAll retrieves a paginated list of all tenants from the database.
// It returns the list of tenants for the current page and the total count of all tenants.
// FindAll 从数据库中检索所有租户的分页列表。
// 它返回当前页的租户列表和所有租户的总数。
func (r *TenantRepoImpl) FindAll(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error) {
	var tenants []*models.Tenant
	var total int64

	// First, count the total number of tenants
	if err := r.db.WithContext(ctx).Model(&models.Tenant{}).Count(&total).Error; err != nil {
		r.logger.Error(ctx, "Failed to count tenants", err)
		return nil, 0, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	// Then, retrieve the paginated result
	err := r.db.WithContext(ctx).
		Limit(limit).
		Offset(offset).
		Find(&tenants).Error
	if err != nil {
		r.logger.Error(ctx, "Failed to retrieve all tenants", err)
		return nil, 0, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	return tenants, total, nil
}

// FindActiveAll retrieves all tenants with an 'active' status.
// FindActiveAll 检索所有状态为 'active' 的租户。
func (r *TenantRepoImpl) FindActiveAll(ctx context.Context) ([]*models.Tenant, error) {
	var tenants []*models.Tenant
	err := r.db.WithContext(ctx).Where("status = ?", constants.TenantStatusActive).Find(&tenants).Error
	if err != nil {
		r.logger.Error(ctx, "Failed to retrieve active tenants", err)
		return nil, err
	}
	return tenants, nil
}

// Exists checks if a tenant with the given ID exists in the database.
// Exists 检查数据库中是否存在具有给定 ID 的租户。
func (r *TenantRepoImpl) Exists(ctx context.Context, tenantID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Tenant{}).Where("tenant_id = ?", tenantID).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// UpdateStatus changes the status of a tenant (e.g., active, suspended).
// It also updates the `UpdatedAt` timestamp.
// UpdateStatus 更改租户的状态（例如，活动、暂停）。
// 它还会更新 `UpdatedAt` 时间戳。
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

// UpdateRateLimitConfig is not yet implemented.
// UpdateRateLimitConfig 尚未实现。
func (r *TenantRepoImpl) UpdateRateLimitConfig(ctx context.Context, tenantID string, config *models.RateLimitConfig) error {
	return fmt.Errorf("not implemented")
}

// UpdateTokenTTLConfig is not yet implemented.
// UpdateTokenTTLConfig 尚未实现。
func (r *TenantRepoImpl) UpdateTokenTTLConfig(ctx context.Context, tenantID string, config *models.TokenTTLConfig) error {
	return fmt.Errorf("not implemented")
}

// UpdateKeyRotationPolicy is not yet implemented.
// UpdateKeyRotationPolicy 尚未实现。
func (r *TenantRepoImpl) UpdateKeyRotationPolicy(ctx context.Context, tenantID string, policy *models.KeyRotationPolicy) error {
	return fmt.Errorf("not implemented")
}

// Delete permanently removes a tenant record from the database.
// This is a hard delete operation.
// Delete 从数据库中永久删除租户记录。
// 这是一个硬删除操作。
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

// GetTenantMetrics is not yet implemented.
// GetTenantMetrics 尚未实现。
func (r *TenantRepoImpl) GetTenantMetrics(ctx context.Context, tenantID string) (*repository.TenantMetrics, error) {
	return nil, fmt.Errorf("not implemented")
}

// GetAllMetrics is not yet implemented.
// GetAllMetrics 尚未实现。
func (r *TenantRepoImpl) GetAllMetrics(ctx context.Context) (*repository.SystemMetrics, error) {
	return nil, fmt.Errorf("not implemented")
}

// IncrementRequestCount is not yet implemented.
// IncrementRequestCount 尚未实现。
func (r *TenantRepoImpl) IncrementRequestCount(ctx context.Context, tenantID string, count int64) error {
	return fmt.Errorf("not implemented")
}

// UpdateLastActivityAt is not yet implemented.
// UpdateLastActivityAt 尚未实现。
func (r *TenantRepoImpl) UpdateLastActivityAt(ctx context.Context, tenantID string, lastActivityAt time.Time) error {
	return fmt.Errorf("not implemented")
}
