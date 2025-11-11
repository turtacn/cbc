package postgres

import (
	"context"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/logger"
	"gorm.io/gorm"
)

// riskRepository provides a PostgreSQL implementation of the repository.RiskRepository interface.
// It handles the persistence and retrieval of tenant risk profiles.
// riskRepository 提供了 repository.RiskRepository 接口的 PostgreSQL 实现。
// 它处理租户风险配置文件的持久化和检索。
type riskRepository struct {
	db  *gorm.DB
	log logger.Logger
}

// NewRiskRepository creates a new instance of the RiskRepository.
// NewRiskRepository 创建一个新的 RiskRepository 实例。
func NewRiskRepository(db *gorm.DB, log logger.Logger) repository.RiskRepository {
	return &riskRepository{
		db:  db,
		log: log,
	}
}

// GetTenantRiskProfile retrieves the risk profile for a specific tenant.
// If a profile is not found for the given tenant ID, it returns a new, default profile
// for that tenant without persisting it. This ensures that a non-nil profile is always returned.
// GetTenantRiskProfile 检索特定租户的风险配置文件。
// 如果找不到给定租户 ID 的配置文件，它将为该租户返回一个新的默认配置文件，但不会持久化它。
// 这确保了始终返回一个非空的配置文件。
func (r *riskRepository) GetTenantRiskProfile(ctx context.Context, tenantID string) (*models.TenantRiskProfile, error) {
	var profile models.TenantRiskProfile
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).First(&profile).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// If no profile exists, return a default, in-memory instance.
			// The application layer can then decide to save it.
			return &models.TenantRiskProfile{TenantID: tenantID}, nil
		}
		r.log.Error(ctx, "Failed to get tenant risk profile", err, logger.String("tenant_id", tenantID))
		return nil, err
	}
	return &profile, nil
}

// UpsertTenantRiskProfile creates a new tenant risk profile or updates an existing one.
// It uses the `Save` method of GORM, which handles both create and update operations based on the primary key.
// UpsertTenantRiskProfile 创建一个新的租户风险配置文件或更新一个现有的。
// 它使用 GORM 的 `Save` 方法，该方法根据主键处理创建和更新操作。
func (r *riskRepository) UpsertTenantRiskProfile(ctx context.Context, profile *models.TenantRiskProfile) error {
	r.log.Debug(ctx, "Upserting tenant risk profile", logger.String("tenant_id", profile.TenantID))
	// GORM's Save method works as an upsert for records with a primary key.
	// It will INSERT if the primary key is zero, otherwise it will UPDATE.
	return r.db.WithContext(ctx).Save(profile).Error
}
