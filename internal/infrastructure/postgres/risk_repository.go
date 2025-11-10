// Package postgres provides a PostgreSQL implementation of the repository interfaces.
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// tenantRiskScoreDBM is the database model for the tenant_risk_scores table.
type tenantRiskScoreDBM struct {
	TenantID        string `gorm:"primaryKey"`
	AnomalyScore    float64
	PredictedThreat string
	LastUpdated     time.Time
}

func (tenantRiskScoreDBM) TableName() string {
	return "tenant_risk_scores"
}

// toDomain converts the database model to a domain model.
func (dbm *tenantRiskScoreDBM) toDomain() *models.TenantRiskProfile {
	return &models.TenantRiskProfile{
		TenantID:        dbm.TenantID,
		AnomalyScore:    dbm.AnomalyScore,
		PredictedThreat: dbm.PredictedThreat,
		LastUpdated:     dbm.LastUpdated,
	}
}

// fromDomain converts a domain model to a database model.
func fromDomain(profile *models.TenantRiskProfile) *tenantRiskScoreDBM {
	return &tenantRiskScoreDBM{
		TenantID:        profile.TenantID,
		AnomalyScore:    profile.AnomalyScore,
		PredictedThreat: profile.PredictedThreat,
		LastUpdated:     profile.LastUpdated,
	}
}

// PostgresRiskRepository is a PostgreSQL implementation of the RiskRepository.
type PostgresRiskRepository struct {
	db *gorm.DB
}

// NewPostgresRiskRepository creates a new PostgresRiskRepository.
func NewPostgresRiskRepository(db *gorm.DB) repository.RiskRepository {
	return &PostgresRiskRepository{db: db}
}

// GetTenantRiskProfile retrieves the risk profile for a given tenant.
func (r *PostgresRiskRepository) GetTenantRiskProfile(ctx context.Context, tenantID string) (*models.TenantRiskProfile, error) {
	var dbm tenantRiskScoreDBM
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).First(&dbm).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Not found is not an error, return nil profile
		}
		return nil, err
	}
	return dbm.toDomain(), nil
}

// UpsertTenantRiskProfile creates or updates the risk profile for a tenant.
func (r *PostgresRiskRepository) UpsertTenantRiskProfile(ctx context.Context, profile *models.TenantRiskProfile) error {
	dbm := fromDomain(profile)
	// Ensure LastUpdated is set to the current time on write
	dbm.LastUpdated = time.Now()

	// Use GORM's OnConflict clause to perform an UPSERT operation.
	// If the tenant_id conflicts, update the specified columns.
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"anomaly_score", "predicted_threat", "last_updated"}),
	}).Create(dbm).Error
}
