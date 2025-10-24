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
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// TenantRepoImpl implements TenantRepository interface using PostgreSQL.
// It manages tenant data with support for multi-tenancy and resource quotas.
type TenantRepoImpl struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewTenantRepository creates a new PostgreSQL-based tenant repository instance.
//
// Parameters:
//   - db: GORM database connection
//   - log: Logger instance for repository operations
//
// Returns:
//   - repository.TenantRepository: Initialized repository implementation
func NewTenantRepository(db *gorm.DB, log logger.Logger) repository.TenantRepository {
	return &TenantRepoImpl{
		db:     db,
		logger: log,
	}
}

// Create registers a new tenant in the system.
// It performs duplicate detection and initializes default quotas.
//
// Parameters:
//   - ctx: Context for timeout and cancellation control
//   - tenant: Tenant model to create
//
// Returns:
//   - error: ErrTenantExists if duplicate found, or database operation error
func (r *TenantRepoImpl) Create(ctx context.Context, tenant *models.Tenant) error {
	startTime := time.Now()

	// Check for existing tenant with same code
	var existingCount int64
	err := r.db.WithContext(ctx).
		Model(&models.Tenant{}).
		Where("code = ?", tenant.Code).
		Count(&existingCount).Error

	if err != nil {
		r.logger.Error("Failed to check for existing tenant",
			"tenant_code", tenant.Code,
			"error", err,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	if existingCount > 0 {
		r.logger.Warn("Tenant already exists", "tenant_code", tenant.Code)
		return errors.ErrTenantExists
	}

	// Set creation timestamp
	now := time.Now()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now

	// Set default status if not specified
	if tenant.Status == "" {
		tenant.Status = models.TenantStatusActive
	}

	// Create tenant record
	if err := r.db.WithContext(ctx).Create(tenant).Error; err != nil {
		r.logger.Error("Failed to create tenant",
			"tenant_code", tenant.Code,
			"tenant_name", tenant.Name,
			"error", err,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	latency := time.Since(startTime)
	r.logger.Info("Tenant created successfully",
		"tenant_id", tenant.ID,
		"tenant_code", tenant.Code,
		"tenant_name", tenant.Name,
		"status", tenant.Status,
		"latency_ms", latency.Milliseconds(),
	)

	return nil
}

// GetByID retrieves a tenant by its unique identifier.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant unique identifier
//
// Returns:
//   - *models.Tenant: Tenant model if found
//   - error: ErrTenantNotFound if not exists, or database operation error
func (r *TenantRepoImpl) GetByID(ctx context.Context, tenantID string) (*models.Tenant, error) {
	var tenant models.Tenant

	err := r.db.WithContext(ctx).
		Where("id = ?", tenantID).
		First(&tenant).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Debug("Tenant not found", "tenant_id", tenantID)
			return nil, errors.ErrTenantNotFound
		}
		r.logger.Error("Failed to retrieve tenant by ID",
			"tenant_id", tenantID,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	return &tenant, nil
}

// GetByCode retrieves a tenant by its unique code.
// This is the primary method for tenant identification.
//
// Parameters:
//   - ctx: Context for timeout control
//   - code: Tenant code
//
// Returns:
//   - *models.Tenant: Tenant model if found
//   - error: ErrTenantNotFound if not exists, or database operation error
func (r *TenantRepoImpl) GetByCode(ctx context.Context, code string) (*models.Tenant, error) {
	var tenant models.Tenant

	err := r.db.WithContext(ctx).
		Where("code = ?", code).
		First(&tenant).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Debug("Tenant not found", "tenant_code", code)
			return nil, errors.ErrTenantNotFound
		}
		r.logger.Error("Failed to retrieve tenant by code",
			"tenant_code", code,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	return &tenant, nil
}

// List retrieves all tenants with pagination support.
//
// Parameters:
//   - ctx: Context for timeout control
//   - limit: Maximum number of tenants to return (0 for no limit)
//   - offset: Number of tenants to skip for pagination
//
// Returns:
//   - []*models.Tenant: List of tenants
//   - error: Database operation error if any
func (r *TenantRepoImpl) List(ctx context.Context, limit, offset int) ([]*models.Tenant, error) {
	var tenants []*models.Tenant

	query := r.db.WithContext(ctx).
		Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}

	if err := query.Find(&tenants).Error; err != nil {
		r.logger.Error("Failed to list tenants",
			"limit", limit,
			"offset", offset,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	r.logger.Debug("Tenants retrieved",
		"count", len(tenants),
		"limit", limit,
		"offset", offset,
	)

	return tenants, nil
}

// ListByStatus retrieves tenants filtered by status.
//
// Parameters:
//   - ctx: Context for timeout control
//   - status: Tenant status filter
//   - limit: Maximum number of tenants to return
//   - offset: Number of tenants to skip for pagination
//
// Returns:
//   - []*models.Tenant: List of tenants matching status
//   - error: Database operation error if any
func (r *TenantRepoImpl) ListByStatus(ctx context.Context, status models.TenantStatus, limit, offset int) ([]*models.Tenant, error) {
	var tenants []*models.Tenant

	query := r.db.WithContext(ctx).
		Where("status = ?", status).
		Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}

	if err := query.Find(&tenants).Error; err != nil {
		r.logger.Error("Failed to list tenants by status",
			"status", status,
			"limit", limit,
			"offset", offset,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	r.logger.Debug("Tenants retrieved by status",
		"status", status,
		"count", len(tenants),
	)

	return tenants, nil
}

// Update modifies an existing tenant record.
// It updates the modification timestamp automatically.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenant: Tenant model with updated fields
//
// Returns:
//   - error: ErrTenantNotFound if not exists, or database operation error
func (r *TenantRepoImpl) Update(ctx context.Context, tenant *models.Tenant) error {
	tenant.UpdatedAt = time.Now()

	result := r.db.WithContext(ctx).
		Model(tenant).
		Where("id = ?", tenant.ID).
		Updates(tenant)

	if result.Error != nil {
		r.logger.Error("Failed to update tenant",
			"tenant_id", tenant.ID,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Warn("Tenant not found for update", "tenant_id", tenant.ID)
		return errors.ErrTenantNotFound
	}

	r.logger.Info("Tenant updated successfully",
		"tenant_id", tenant.ID,
		"tenant_code", tenant.Code,
	)

	return nil
}

// UpdateStatus changes tenant status (active, suspended, deleted).
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//   - status: New tenant status
//
// Returns:
//   - error: Database operation error if any
func (r *TenantRepoImpl) UpdateStatus(ctx context.Context, tenantID string, status models.TenantStatus) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&models.Tenant{}).
		Where("id = ?", tenantID).
		Updates(map[string]interface{}{
			"status":     status,
			"updated_at": now,
		})

	if result.Error != nil {
		r.logger.Error("Failed to update tenant status",
			"tenant_id", tenantID,
			"status", status,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return errors.ErrTenantNotFound
	}

	r.logger.Info("Tenant status updated",
		"tenant_id", tenantID,
		"status", status,
	)

	return nil
}

// Delete removes a tenant record from the system.
// This is a soft delete that marks the tenant as inactive.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//
// Returns:
//   - error: Database operation error if any
func (r *TenantRepoImpl) Delete(ctx context.Context, tenantID string) error {
	result := r.db.WithContext(ctx).
		Where("id = ?", tenantID).
		Delete(&models.Tenant{})

	if result.Error != nil {
		r.logger.Error("Failed to delete tenant",
			"tenant_id", tenantID,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Debug("Tenant not found for deletion", "tenant_id", tenantID)
		return errors.ErrTenantNotFound
	}

	r.logger.Info("Tenant deleted successfully", "tenant_id", tenantID)
	return nil
}

// Count returns the total number of tenants in the system.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - int64: Total tenant count
//   - error: Database operation error if any
func (r *TenantRepoImpl) Count(ctx context.Context) (int64, error) {
	var count int64

	err := r.db.WithContext(ctx).
		Model(&models.Tenant{}).
		Count(&count).Error

	if err != nil {
		r.logger.Error("Failed to count tenants", "error", err)
		return 0, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	return count, nil
}

// CountByStatus returns the number of tenants with specific status.
//
// Parameters:
//   - ctx: Context for timeout control
//   - status: Tenant status filter
//
// Returns:
//   - int64: Tenant count for the status
//   - error: Database operation error if any
func (r *TenantRepoImpl) CountByStatus(ctx context.Context, status models.TenantStatus) (int64, error) {
	var count int64

	err := r.db.WithContext(ctx).
		Model(&models.Tenant{}).
		Where("status = ?", status).
		Count(&count).Error

	if err != nil {
		r.logger.Error("Failed to count tenants by status",
			"status", status,
			"error", err,
		)
		return 0, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	return count, nil
}

// UpdateQuota updates tenant resource quotas.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//   - quotaField: Name of quota field to update
//   - value: New quota value
//
// Returns:
//   - error: Database operation error if any
func (r *TenantRepoImpl) UpdateQuota(ctx context.Context, tenantID string, quotaField string, value int64) error {
	now := time.Now()

	updates := map[string]interface{}{
		quotaField:   value,
		"updated_at": now,
	}

	result := r.db.WithContext(ctx).
		Model(&models.Tenant{}).
		Where("id = ?", tenantID).
		Updates(updates)

	if result.Error != nil {
		r.logger.Error("Failed to update tenant quota",
			"tenant_id", tenantID,
			"quota_field", quotaField,
			"value", value,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return errors.ErrTenantNotFound
	}

	r.logger.Info("Tenant quota updated",
		"tenant_id", tenantID,
		"quota_field", quotaField,
		"value", value,
	)

	return nil
}

// IncrementUsage increments tenant resource usage counter.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//   - usageField: Name of usage field to increment
//   - delta: Amount to increment (can be negative for decrement)
//
// Returns:
//   - error: Database operation error if any
func (r *TenantRepoImpl) IncrementUsage(ctx context.Context, tenantID string, usageField string, delta int64) error {
	now := time.Now()

	var updateExpr string
	if delta >= 0 {
		updateExpr = fmt.Sprintf("%s + %d", usageField, delta)
	} else {
		updateExpr = fmt.Sprintf("%s - %d", usageField, -delta)
	}

	result := r.db.WithContext(ctx).
		Model(&models.Tenant{}).
		Where("id = ?", tenantID).
		Updates(map[string]interface{}{
			usageField:   gorm.Expr(updateExpr),
			"updated_at": now,
		})

	if result.Error != nil {
		r.logger.Error("Failed to increment tenant usage",
			"tenant_id", tenantID,
			"usage_field", usageField,
			"delta", delta,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return errors.ErrTenantNotFound
	}

	r.logger.Debug("Tenant usage incremented",
		"tenant_id", tenantID,
		"usage_field", usageField,
		"delta", delta,
	)

	return nil
}

// CheckQuota verifies if tenant has available quota for a resource.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//   - quotaField: Name of quota field to check
//   - usageField: Name of usage field to compare
//   - required: Required quota amount
//
// Returns:
//   - bool: True if quota is available
//   - error: Database operation error if any
func (r *TenantRepoImpl) CheckQuota(ctx context.Context, tenantID string, quotaField, usageField string, required int64) (bool, error) {
	var result struct {
		Quota int64
		Usage int64
	}

	err := r.db.WithContext(ctx).
		Model(&models.Tenant{}).
		Select(fmt.Sprintf("%s as quota, %s as usage", quotaField, usageField)).
		Where("id = ?", tenantID).
		First(&result).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, errors.ErrTenantNotFound
		}
		r.logger.Error("Failed to check tenant quota",
			"tenant_id", tenantID,
			"quota_field", quotaField,
			"usage_field", usageField,
			"error", err,
		)
		return false, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	available := result.Quota - result.Usage
	hasQuota := available >= required

	r.logger.Debug("Tenant quota checked",
		"tenant_id", tenantID,
		"quota", result.Quota,
		"usage", result.Usage,
		"available", available,
		"required", required,
		"has_quota", hasQuota,
	)

	return hasQuota, nil
}

// GetTenantStatistics retrieves comprehensive statistics for a tenant.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//
// Returns:
//   - map[string]interface{}: Statistics including quotas, usage, and limits
//   - error: Database operation error if any
func (r *TenantRepoImpl) GetTenantStatistics(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	var tenant models.Tenant

	err := r.db.WithContext(ctx).
		Where("id = ?", tenantID).
		First(&tenant).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.ErrTenantNotFound
		}
		r.logger.Error("Failed to retrieve tenant statistics",
			"tenant_id", tenantID,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	stats := map[string]interface{}{
		"tenant_id":          tenant.ID,
		"tenant_code":        tenant.Code,
		"tenant_name":        tenant.Name,
		"status":             tenant.Status,
		"max_agents":         tenant.MaxAgents,
		"current_agents":     tenant.CurrentAgents,
		"max_devices":        tenant.MaxDevices,
		"current_devices":    tenant.CurrentDevices,
		"max_sessions":       tenant.MaxSessions,
		"current_sessions":   tenant.CurrentSessions,
		"storage_quota_gb":   tenant.StorageQuotaGB,
		"storage_used_gb":    tenant.StorageUsedGB,
		"created_at":         tenant.CreatedAt,
		"updated_at":         tenant.UpdatedAt,
		"agent_utilization":  float64(tenant.CurrentAgents) / float64(tenant.MaxAgents) * 100,
		"device_utilization": float64(tenant.CurrentDevices) / float64(tenant.MaxDevices) * 100,
		"storage_utilization": float64(tenant.StorageUsedGB) / float64(tenant.StorageQuotaGB) * 100,
	}

	r.logger.Debug("Tenant statistics retrieved",
		"tenant_id", tenantID,
		"stats", stats,
	)

	return stats, nil
}

// BatchUpdateStatus updates status for multiple tenants.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantIDs: List of tenant identifiers
//   - status: New status to set
//
// Returns:
//   - error: Database operation error if any
func (r *TenantRepoImpl) BatchUpdateStatus(ctx context.Context, tenantIDs []string, status models.TenantStatus) error {
	if len(tenantIDs) == 0 {
		return nil
	}

	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&models.Tenant{}).
		Where("id IN ?", tenantIDs).
		Updates(map[string]interface{}{
			"status":     status,
			"updated_at": now,
		})

	if result.Error != nil {
		r.logger.Error("Failed to batch update tenant status",
			"tenant_count", len(tenantIDs),
			"status", status,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	r.logger.Info("Batch tenant status updated",
		"updated_count", result.RowsAffected,
		"requested_count", len(tenantIDs),
		"status", status,
	)

	return nil
}

// SearchTenants searches tenants by name or code with pagination.
//
// Parameters:
//   - ctx: Context for timeout control
//   - keyword: Search keyword for name or code
//   - limit: Maximum number of results
//   - offset: Offset for pagination
//
// Returns:
//   - []*models.Tenant: List of matching tenants
//   - error: Database operation error if any
func (r *TenantRepoImpl) SearchTenants(ctx context.Context, keyword string, limit, offset int) ([]*models.Tenant, error) {
	var tenants []*models.Tenant

	searchPattern := "%" + keyword + "%"
	query := r.db.WithContext(ctx).
		Where("name ILIKE ? OR code ILIKE ?", searchPattern, searchPattern).
		Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}

	if err := query.Find(&tenants).Error; err != nil {
		r.logger.Error("Failed to search tenants",
			"keyword", keyword,
			"limit", limit,
			"offset", offset,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	r.logger.Debug("Tenants search completed",
		"keyword", keyword,
		"result_count", len(tenants),
	)

	return tenants, nil
}

// GetExpiringSoon retrieves tenants whose subscription is expiring soon.
//
// Parameters:
//   - ctx: Context for timeout control
//   - days: Number of days threshold
//
// Returns:
//   - []*models.Tenant: List of tenants expiring soon
//   - error: Database operation error if any
func (r *TenantRepoImpl) GetExpiringSoon(ctx context.Context, days int) ([]*models.Tenant, error) {
	var tenants []*models.Tenant

	expiryThreshold := time.Now().AddDate(0, 0, days)

	err := r.db.WithContext(ctx).
		Where("expires_at IS NOT NULL AND expires_at <= ? AND status = ?",
			expiryThreshold, models.TenantStatusActive).
		Order("expires_at ASC").
		Find(&tenants).Error

	if err != nil {
		r.logger.Error("Failed to retrieve expiring tenants",
			"days", days,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	r.logger.Info("Expiring tenants retrieved",
		"days", days,
		"count", len(tenants),
	)

	return tenants, nil
}

// Personal.AI order the ending
