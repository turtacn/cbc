package application

import (
	"context"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/internal/domain/service"
)

// riskOracle implements the service.RiskOracle interface.
type riskOracle struct {
	riskRepo repository.RiskRepository
}

// NewRiskOracle creates a new RiskOracle service.
func NewRiskOracle(riskRepo repository.RiskRepository) service.RiskOracle {
	return &riskOracle{riskRepo: riskRepo}
}

// GetTenantRisk retrieves the risk profile for a given tenant.
// If no profile is found in the repository, it returns a default low-risk profile.
func (ro *riskOracle) GetTenantRisk(ctx context.Context, tenantID string) (*models.TenantRiskProfile, error) {
	profile, err := ro.riskRepo.GetTenantRiskProfile(ctx, tenantID)
	if err != nil {
		return nil, err // An actual error occurred
	}
	if profile == nil {
		// No profile found, return a default low-risk profile
		return &models.TenantRiskProfile{
			TenantID:        tenantID,
			AnomalyScore:    0.0,
			PredictedThreat: "low",
		}, nil
	}
	return profile, nil
}
