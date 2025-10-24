// Package postgres implements PostgreSQL-based device repository for trusted device management.
// It provides device fingerprint verification, trust scoring, and device lifecycle management.
package postgres

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// DeviceRepoImpl implements DeviceRepository interface using PostgreSQL.
// It manages device registration, trust scoring, and fingerprint validation.
type DeviceRepoImpl struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewDeviceRepository creates a new PostgreSQL-based device repository instance.
//
// Parameters:
//   - db: GORM database connection
//   - log: Logger instance for repository operations
//
// Returns:
//   - repository.DeviceRepository: Initialized repository implementation
func NewDeviceRepository(db *gorm.DB, log logger.Logger) repository.DeviceRepository {
	return &DeviceRepoImpl{
		db:     db,
		logger: log,
	}
}

// Create registers a new device in the system.
// It performs duplicate detection based on fingerprint and agent combination.
//
// Parameters:
//   - ctx: Context for timeout and cancellation control
//   - device: Device model to create
//
// Returns:
//   - error: ErrDeviceExists if duplicate found, or database operation error
func (r *DeviceRepoImpl) Create(ctx context.Context, device *models.Device) error {
	startTime := time.Now()

	// Check for existing device with same fingerprint and agent
	var existingCount int64
	err := r.db.WithContext(ctx).
		Model(&models.Device{}).
		Where("fingerprint = ? AND agent_id = ?", device.Fingerprint, device.AgentID).
		Count(&existingCount).Error

	if err != nil {
		r.logger.Error("Failed to check for existing device",
			"agent_id", device.AgentID,
			"fingerprint", device.Fingerprint,
			"error", err,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	if existingCount > 0 {
		r.logger.Warn("Device already exists",
			"agent_id", device.AgentID,
			"fingerprint", device.Fingerprint,
		)
		return errors.ErrDeviceExists
	}

	// Set creation timestamp
	now := time.Now()
	device.FirstSeenAt = now
	device.LastSeenAt = now
	device.CreatedAt = now
	device.UpdatedAt = now

	// Create device record
	if err := r.db.WithContext(ctx).Create(device).Error; err != nil {
		r.logger.Error("Failed to create device",
			"agent_id", device.AgentID,
			"fingerprint", device.Fingerprint,
			"error", err,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	latency := time.Since(startTime)
	r.logger.Info("Device created successfully",
		"device_id", device.ID,
		"agent_id", device.AgentID,
		"fingerprint", device.Fingerprint,
		"trust_score", device.TrustScore,
		"latency_ms", latency.Milliseconds(),
	)

	return nil
}

// GetByID retrieves a device by its unique identifier.
//
// Parameters:
//   - ctx: Context for timeout control
//   - deviceID: Device unique identifier
//
// Returns:
//   - *models.Device: Device model if found
//   - error: ErrDeviceNotFound if not exists, or database operation error
func (r *DeviceRepoImpl) GetByID(ctx context.Context, deviceID string) (*models.Device, error) {
	var device models.Device

	err := r.db.WithContext(ctx).
		Where("id = ?", deviceID).
		First(&device).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Debug("Device not found", "device_id", deviceID)
			return nil, errors.ErrDeviceNotFound
		}
		r.logger.Error("Failed to retrieve device by ID",
			"device_id", deviceID,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	return &device, nil
}

// GetByFingerprint retrieves a device by fingerprint and agent ID.
// This is the primary method for device authentication and verification.
//
// Parameters:
//   - ctx: Context for timeout control
//   - fingerprint: Device fingerprint hash
//   - agentID: Agent identifier
//
// Returns:
//   - *models.Device: Device model if found
//   - error: ErrDeviceNotFound if not exists, or database operation error
func (r *DeviceRepoImpl) GetByFingerprint(ctx context.Context, fingerprint, agentID string) (*models.Device, error) {
	var device models.Device

	err := r.db.WithContext(ctx).
		Where("fingerprint = ? AND agent_id = ?", fingerprint, agentID).
		First(&device).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Debug("Device not found by fingerprint",
				"fingerprint", fingerprint,
				"agent_id", agentID,
			)
			return nil, errors.ErrDeviceNotFound
		}
		r.logger.Error("Failed to retrieve device by fingerprint",
			"fingerprint", fingerprint,
			"agent_id", agentID,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	return &device, nil
}

// ListByAgent retrieves all devices associated with an agent.
//
// Parameters:
//   - ctx: Context for timeout control
//   - agentID: Agent identifier
//   - limit: Maximum number of devices to return (0 for no limit)
//   - offset: Number of devices to skip for pagination
//
// Returns:
//   - []*models.Device: List of devices
//   - error: Database operation error if any
func (r *DeviceRepoImpl) ListByAgent(ctx context.Context, agentID string, limit, offset int) ([]*models.Device, error) {
	var devices []*models.Device

	query := r.db.WithContext(ctx).
		Where("agent_id = ?", agentID).
		Order("last_seen_at DESC")

	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}

	if err := query.Find(&devices).Error; err != nil {
		r.logger.Error("Failed to list devices by agent",
			"agent_id", agentID,
			"limit", limit,
			"offset", offset,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	r.logger.Debug("Devices retrieved for agent",
		"agent_id", agentID,
		"count", len(devices),
		"limit", limit,
		"offset", offset,
	)

	return devices, nil
}

// Update modifies an existing device record.
// It updates the modification timestamp automatically.
//
// Parameters:
//   - ctx: Context for timeout control
//   - device: Device model with updated fields
//
// Returns:
//   - error: ErrDeviceNotFound if not exists, or database operation error
func (r *DeviceRepoImpl) Update(ctx context.Context, device *models.Device) error {
	device.UpdatedAt = time.Now()

	result := r.db.WithContext(ctx).
		Model(device).
		Where("id = ?", device.ID).
		Updates(device)

	if result.Error != nil {
		r.logger.Error("Failed to update device",
			"device_id", device.ID,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Warn("Device not found for update", "device_id", device.ID)
		return errors.ErrDeviceNotFound
	}

	r.logger.Info("Device updated successfully",
		"device_id", device.ID,
		"agent_id", device.AgentID,
	)

	return nil
}

// UpdateLastSeen updates the last seen timestamp and increments access count.
// This is a high-frequency operation optimized for performance.
//
// Parameters:
//   - ctx: Context for timeout control
//   - deviceID: Device identifier
//
// Returns:
//   - error: Database operation error if any
func (r *DeviceRepoImpl) UpdateLastSeen(ctx context.Context, deviceID string) error {
	now := time.Now()

	result := r.db.WithContext(ctx).
		Model(&models.Device{}).
		Where("id = ?", deviceID).
		Updates(map[string]interface{}{
			"last_seen_at":  now,
			"access_count":  gorm.Expr("access_count + 1"),
			"updated_at":    now,
		})

	if result.Error != nil {
		r.logger.Error("Failed to update device last seen",
			"device_id", deviceID,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Debug("Device not found for last seen update", "device_id", deviceID)
		return errors.ErrDeviceNotFound
	}

	r.logger.Debug("Device last seen updated", "device_id", deviceID)
	return nil
}

// UpdateTrustScore updates device trust score based on behavior analysis.
//
// Parameters:
//   - ctx: Context for timeout control
//   - deviceID: Device identifier
//   - trustScore: New trust score (0.0 to 1.0)
//
// Returns:
//   - error: Database operation error if any
func (r *DeviceRepoImpl) UpdateTrustScore(ctx context.Context, deviceID string, trustScore float64) error {
	// Validate trust score range
	if trustScore < 0.0 || trustScore > 1.0 {
		return fmt.Errorf("%w: trust score must be between 0.0 and 1.0", errors.ErrInvalidInput)
	}

	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&models.Device{}).
		Where("id = ?", deviceID).
		Updates(map[string]interface{}{
			"trust_score": trustScore,
			"updated_at":  now,
		})

	if result.Error != nil {
		r.logger.Error("Failed to update device trust score",
			"device_id", deviceID,
			"trust_score", trustScore,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return errors.ErrDeviceNotFound
	}

	r.logger.Info("Device trust score updated",
		"device_id", deviceID,
		"trust_score", trustScore,
	)

	return nil
}

// SetTrusted marks a device as trusted or untrusted.
// Trusted devices may bypass certain security checks.
//
// Parameters:
//   - ctx: Context for timeout control
//   - deviceID: Device identifier
//   - trusted: Trust status
//
// Returns:
//   - error: Database operation error if any
func (r *DeviceRepoImpl) SetTrusted(ctx context.Context, deviceID string, trusted bool) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&models.Device{}).
		Where("id = ?", deviceID).
		Updates(map[string]interface{}{
			"is_trusted": trusted,
			"updated_at": now,
		})

	if result.Error != nil {
		r.logger.Error("Failed to update device trust status",
			"device_id", deviceID,
			"trusted", trusted,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return errors.ErrDeviceNotFound
	}

	r.logger.Info("Device trust status updated",
		"device_id", deviceID,
		"is_trusted", trusted,
	)

	return nil
}

// Delete removes a device record from the system.
// This is a soft delete that marks the device as inactive.
//
// Parameters:
//   - ctx: Context for timeout control
//   - deviceID: Device identifier
//
// Returns:
//   - error: Database operation error if any
func (r *DeviceRepoImpl) Delete(ctx context.Context, deviceID string) error {
	result := r.db.WithContext(ctx).
		Where("id = ?", deviceID).
		Delete(&models.Device{})

	if result.Error != nil {
		r.logger.Error("Failed to delete device",
			"device_id", deviceID,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Debug("Device not found for deletion", "device_id", deviceID)
		return errors.ErrDeviceNotFound
	}

	r.logger.Info("Device deleted successfully", "device_id", deviceID)
	return nil
}

// DeleteByAgent removes all devices associated with an agent.
// Used during agent cleanup or deregistration.
//
// Parameters:
//   - ctx: Context for timeout control
//   - agentID: Agent identifier
//
// Returns:
//   - error: Database operation error if any
func (r *DeviceRepoImpl) DeleteByAgent(ctx context.Context, agentID string) error {
	result := r.db.WithContext(ctx).
		Where("agent_id = ?", agentID).
		Delete(&models.Device{})

	if result.Error != nil {
		r.logger.Error("Failed to delete devices by agent",
			"agent_id", agentID,
			"error", result.Error,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	r.logger.Info("Devices deleted for agent",
		"agent_id", agentID,
		"deleted_count", result.RowsAffected,
	)

	return nil
}

// CountByAgent returns the number of devices registered for an agent.
//
// Parameters:
//   - ctx: Context for timeout control
//   - agentID: Agent identifier
//
// Returns:
//   - int64: Device count
//   - error: Database operation error if any
func (r *DeviceRepoImpl) CountByAgent(ctx context.Context, agentID string) (int64, error) {
	var count int64

	err := r.db.WithContext(ctx).
		Model(&models.Device{}).
		Where("agent_id = ?", agentID).
		Count(&count).Error

	if err != nil {
		r.logger.Error("Failed to count devices by agent",
			"agent_id", agentID,
			"error", err,
		)
		return 0, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	return count, nil
}

// GetTrustedDevices retrieves all trusted devices for an agent.
//
// Parameters:
//   - ctx: Context for timeout control
//   - agentID: Agent identifier
//
// Returns:
//   - []*models.Device: List of trusted devices
//   - error: Database operation error if any
func (r *DeviceRepoImpl) GetTrustedDevices(ctx context.Context, agentID string) ([]*models.Device, error) {
	var devices []*models.Device

	err := r.db.WithContext(ctx).
		Where("agent_id = ? AND is_trusted = ?", agentID, true).
		Order("last_seen_at DESC").
		Find(&devices).Error

	if err != nil {
		r.logger.Error("Failed to retrieve trusted devices",
			"agent_id", agentID,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	r.logger.Debug("Trusted devices retrieved",
		"agent_id", agentID,
		"count", len(devices),
	)

	return devices, nil
}

// CleanupInactiveDevices removes devices that haven't been seen within the specified duration.
// This helps maintain database hygiene and removes stale device records.
//
// Parameters:
//   - ctx: Context for timeout control
//   - inactiveDuration: Time duration after which devices are considered inactive
//
// Returns:
//   - int64: Number of devices cleaned up
//   - error: Database operation error if any
func (r *DeviceRepoImpl) CleanupInactiveDevices(ctx context.Context, inactiveDuration time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-inactiveDuration)

	result := r.db.WithContext(ctx).
		Where("last_seen_at < ? AND is_trusted = ?", cutoffTime, false).
		Delete(&models.Device{})

	if result.Error != nil {
		r.logger.Error("Failed to cleanup inactive devices",
			"cutoff_time", cutoffTime,
			"error", result.Error,
		)
		return 0, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	deletedCount := result.RowsAffected
	r.logger.Info("Inactive devices cleaned up",
		"deleted_count", deletedCount,
		"cutoff_time", cutoffTime,
		"inactive_duration_days", inactiveDuration.Hours()/24,
	)

	return deletedCount, nil
}

// GetDevicesByTrustScore retrieves devices with trust score within specified range.
// Useful for security analytics and risk assessment.
//
// Parameters:
//   - ctx: Context for timeout control
//   - minScore: Minimum trust score (inclusive)
//   - maxScore: Maximum trust score (inclusive)
//   - limit: Maximum number of devices to return
//
// Returns:
//   - []*models.Device: List of devices matching criteria
//   - error: Database operation error if any
func (r *DeviceRepoImpl) GetDevicesByTrustScore(ctx context.Context, minScore, maxScore float64, limit int) ([]*models.Device, error) {
	var devices []*models.Device

	query := r.db.WithContext(ctx).
		Where("trust_score >= ? AND trust_score <= ?", minScore, maxScore).
		Order("trust_score ASC, last_seen_at DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Find(&devices).Error; err != nil {
		r.logger.Error("Failed to retrieve devices by trust score",
			"min_score", minScore,
			"max_score", maxScore,
			"limit", limit,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}

	r.logger.Debug("Devices retrieved by trust score",
		"min_score", minScore,
		"max_score", maxScore,
		"count", len(devices),
	)

	return devices, nil
}

// BulkUpdateTrustScores updates trust scores for multiple devices in a single transaction.
// Optimized for batch processing and periodic trust recalculation.
//
// Parameters:
//   - ctx: Context for timeout control
//   - updates: Map of device ID to new trust score
//
// Returns:
//   - error: Database operation error if any
func (r *DeviceRepoImpl) BulkUpdateTrustScores(ctx context.Context, updates map[string]float64) error {
	if len(updates) == 0 {
		return nil
	}

	// Use transaction for atomic updates
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now()

		for deviceID, trustScore := range updates {
			// Validate trust score
			if trustScore < 0.0 || trustScore > 1.0 {
				r.logger.Warn("Invalid trust score in bulk update",
					"device_id", deviceID,
					"trust_score", trustScore,
				)
				continue
			}

			result := tx.Model(&models.Device{}).
				Where("id = ?", deviceID).
				Updates(map[string]interface{}{
					"trust_score": trustScore,
					"updated_at":  now,
				})

			if result.Error != nil {
				r.logger.Error("Failed to update device in bulk operation",
					"device_id", deviceID,
					"trust_score", trustScore,
					"error", result.Error,
				)
				return result.Error
			}
		}

		return nil
	})

	if err != nil {
		r.logger.Error("Bulk trust score update failed",
			"update_count", len(updates),
			"error", err,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	r.logger.Info("Bulk trust scores updated successfully",
		"update_count", len(updates),
	)

	return nil
}

// GetDeviceStatsByAgent retrieves device statistics for an agent.
//
// Parameters:
//   - ctx: Context for timeout control
//   - agentID: Agent identifier
//
// Returns:
//   - map[string]interface{}: Statistics including total, trusted, and average trust score
//   - error: Database operation error if any
func (r *DeviceRepoImpl) GetDeviceStatsByAgent(ctx context.Context, agentID string) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total device count
	var totalCount int64
	if err := r.db.WithContext(ctx).
		Model(&models.Device{}).
		Where("agent_id = ?", agentID).
		Count(&totalCount).Error; err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}
	stats["total_devices"] = totalCount

	// Trusted device count
	var trustedCount int64
	if err := r.db.WithContext(ctx).
		Model(&models.Device{}).
		Where("agent_id = ? AND is_trusted = ?", agentID, true).
		Count(&trustedCount).Error; err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}
	stats["trusted_devices"] = trustedCount

	// Average trust score
	var avgTrustScore float64
	if err := r.db.WithContext(ctx).
		Model(&models.Device{}).
		Where("agent_id = ?", agentID).
		Select("COALESCE(AVG(trust_score), 0)").
		Scan(&avgTrustScore).Error; err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}
	stats["average_trust_score"] = avgTrustScore

	// Recently active devices (last 7 days)
	sevenDaysAgo := time.Now().AddDate(0, 0, -7)
	var recentCount int64
	if err := r.db.WithContext(ctx).
		Model(&models.Device{}).
		Where("agent_id = ? AND last_seen_at > ?", agentID, sevenDaysAgo).
		Count(&recentCount).Error; err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseQuery, err)
	}
	stats["recently_active"] = recentCount

	r.logger.Debug("Device statistics retrieved",
		"agent_id", agentID,
		"stats", stats,
	)

	return stats, nil
}

//Personal.AI order the ending
