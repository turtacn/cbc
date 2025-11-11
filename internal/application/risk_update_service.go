package application

import (
	"context"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
)

//go:generate mockery --name RiskUpdateService --output mocks --outpkg mocks

// RiskUpdateService defines the application service interface for receiving and persisting tenant risk profile updates.
// This service is typically exposed via an internal API for consumption by external analysis systems.
// RiskUpdateService 定义了用于接收和持久化租户风险配置文件更新的应用程序服务接口。
// 此服务通常通过内部 API 暴露，供外部分析系统使用。
type RiskUpdateService interface {
	// UpdateTenantRisk creates or updates the risk profile for a specific tenant.
	// UpdateTenantRisk 创建或更新特定租户的风险配置文件。
	UpdateTenantRisk(ctx context.Context, tenantID string, score float64, threat string) error
}

// riskUpdateService is the concrete implementation of the RiskUpdateService interface.
// riskUpdateService 是 RiskUpdateService 接口的具体实现。
type riskUpdateService struct {
	riskRepo repository.RiskRepository
}

// NewRiskUpdateService creates a new instance of the RiskUpdateService.
// NewRiskUpdateService 创建一个新的 RiskUpdateService 实例。
func NewRiskUpdateService(riskRepo repository.RiskRepository) RiskUpdateService {
	return &riskUpdateService{riskRepo: riskRepo}
}

// UpdateTenantRisk constructs a TenantRiskProfile model from the input and uses the repository to persist it.
// UpdateTenantRisk 根据输入构建一个 TenantRiskProfile 模型，并使用存储库将其持久化。
func (s *riskUpdateService) UpdateTenantRisk(ctx context.Context, tenantID string, score float64, threat string) error {
	profile := &models.TenantRiskProfile{
		TenantID:        tenantID,
		AnomalyScore:    score,
		PredictedThreat: threat,
	}

	return s.riskRepo.UpsertTenantRiskProfile(ctx, profile)
}
