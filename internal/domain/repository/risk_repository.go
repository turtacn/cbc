package repository

import (
	"context"
	"github.com/turtacn/cbc/internal/domain/models"
)

//go:generate mockery --name RiskRepository --output ../repository/mocks --filename risk_repository.go
type RiskRepository interface {
	// GetTenantRiskProfile retrieves the risk profile for a given tenant.
	// If the profile is not found, it should return (nil, nil) to allow the
	// service layer to handle default risk profiles.
	GetTenantRiskProfile(ctx context.Context, tenantID string) (*models.TenantRiskProfile, error)

	// UpsertTenantRiskProfile creates or updates the risk profile for a tenant.
	UpsertTenantRiskProfile(ctx context.Context, profile *models.TenantRiskProfile) error
}
