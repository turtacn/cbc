package repository

import (
	"context"
	"github.com/turtacn/cbc/internal/domain/models"
)

//go:generate mockery --name RiskRepository --output ../repository/mocks --filename risk_repository.go

// RiskRepository defines the interface for persisting and retrieving tenant risk profiles.
// These profiles are used by the policy engine to make dynamic, risk-based decisions.
// RiskRepository 定义了用于持久化和检索租户风险配置文件的接口。
// 策略引擎使用这些配置文件来制定动态的、基于风险的决策。
type RiskRepository interface {
	// GetTenantRiskProfile retrieves the risk profile for a given tenant.
	// If a profile for the tenant is not found, it should return (nil, nil)
	// to allow the service layer to apply a default or baseline risk profile.
	// GetTenantRiskProfile 检索给定租户的风险配置文件。
	// 如果未找到租户的配置文件，它应返回 (nil, nil)
	// 以允许服务层应用默认或基线风险配置文件。
	GetTenantRiskProfile(ctx context.Context, tenantID string) (*models.TenantRiskProfile, error)

	// UpsertTenantRiskProfile creates a new risk profile or updates an existing one for a tenant.
	// This method is used by internal services that receive risk data from external analysis systems.
	// UpsertTenantRiskProfile 为租户创建新的风险配置文件或更新现有的风险配置文件。
	// 该方法由从外部分析系统接收风险数据的内部服务使用。
	UpsertTenantRiskProfile(ctx context.Context, profile *models.TenantRiskProfile) error
}
