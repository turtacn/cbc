package application

import (
	"context"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
)

//go:generate mockery --name RiskUpdateService --output mocks --outpkg mocks
// RiskUpdateService defines the interface for updating tenant risk scores.
type RiskUpdateService interface {
	UpdateTenantRisk(ctx context.Context, tenantID string, score float64, threat string) error
}

// riskUpdateService implements the RiskUpdateService interface.
type riskUpdateService struct {
	riskRepo repository.RiskRepository
}

// NewRiskUpdateService creates a new RiskUpdateService.
func NewRiskUpdateService(riskRepo repository.RiskRepository) RiskUpdateService {
	return &riskUpdateService{riskRepo: riskRepo}
}

// UpdateTenantRisk handles the logic for creating or updating a tenant's risk profile.
func (s *riskUpdateService) UpdateTenantRisk(ctx context.Context, tenantID string, score float64, threat string) error {
	profile := &models.TenantRiskProfile{
		TenantID:        tenantID,
		AnomalyScore:    score,
		PredictedThreat: threat,
	}

	return s.riskRepo.UpsertTenantRiskProfile(ctx, profile)
}
