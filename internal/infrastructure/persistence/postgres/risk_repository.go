package postgres

import (
	"context"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/logger"
	"gorm.io/gorm"
)

type riskRepository struct {
	db  *gorm.DB
	log logger.Logger
}

func NewRiskRepository(db *gorm.DB, log logger.Logger) repository.RiskRepository {
	return &riskRepository{
		db:  db,
		log: log,
	}
}

func (r *riskRepository) GetTenantRiskProfile(ctx context.Context, tenantID string) (*models.TenantRiskProfile, error) {
	var profile models.TenantRiskProfile
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).First(&profile).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return &models.TenantRiskProfile{TenantID: tenantID}, nil // Return default if not found
		}
		return nil, err
	}
	return &profile, nil
}

func (r *riskRepository) UpsertTenantRiskProfile(ctx context.Context, profile *models.TenantRiskProfile) error {
	return r.db.WithContext(ctx).Save(profile).Error
}
