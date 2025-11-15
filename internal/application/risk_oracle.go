package application

import (
	"context"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/internal/domain/service"
)

// riskOracle implements the service.RiskOracle interface, providing a concrete way to fetch tenant risk profiles.
// riskOracle实现了service.RiskOracle接口，提供了一种具体的方式来获取租户风险画像。
type riskOracle struct {
	riskRepo repository.RiskRepository
}

// NewRiskOracle creates a new RiskOracle service that uses the given repository to fetch risk data.
// NewRiskOracle 创建一个新的RiskOracle服务，该服务使用给定的存储库来获取风险数据。
func NewRiskOracle(riskRepo repository.RiskRepository) service.RiskOracle {
	return &riskOracle{riskRepo: riskRepo}
}

// GetTenantRisk retrieves the risk profile for a given tenant.
// If no specific profile is found in the repository, it gracefully falls back to a default low-risk profile.
// GetTenantRisk 检索给定租户的风险画像。
//如果在存储库中没有找到特定的画像，它会平滑地回退到默认的低风险画像。
func (ro *riskOracle) GetTenantRisk(ctx context.Context, tenantID, agentID string) (*models.TenantRiskProfile, error) {
	profile, err := ro.riskRepo.GetTenantRiskProfile(ctx, tenantID)
	if err != nil {
		return nil, err // An actual error occurred.
	}
	if profile == nil {
		// No profile found, return a default low-risk profile.
		return &models.TenantRiskProfile{
			TenantID:        tenantID,
			AnomalyScore:    0.0,
			PredictedThreat: "low",
		}, nil
	}
	return profile, nil
}
