//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"github.com/turtacn/cbc/internal/application"
	"github.com/turtacn/cbc/internal/domain/models"
	repomocks "github.com/turtacn/cbc/internal/domain/repository/mocks"
	"github.com/turtacn/cbc/internal/domain/service"
	servicemocks "github.com/turtacn/cbc/internal/domain/service/mocks"
	"github.com/turtacn/cbc/internal/infrastructure/policy"
	"github.com/turtacn/cbc/pkg/logger"
)

type AIDrivenSecuritySuite struct {
	suite.Suite
	kms          service.KeyManagementService
	riskOracle   service.RiskOracle
	policyEngine service.PolicyEngine
	tenantRepo   *repomocks.TenantRepository
	keyRepo      *repomocks.KeyRepository
	riskRepo     *repomocks.RiskRepository
	klr          *servicemocks.KeyLifecycleRegistry
	keyProvider  *servicemocks.KeyProvider
}

func (s *AIDrivenSecuritySuite) SetupSuite() {
	// Create a temporary policy file
	policyFile, err := os.CreateTemp("", "policies-*.yaml")
	s.Require().NoError(err)
	_, err = policyFile.WriteString(`
L3:
  minKeySize: 2048
  blockOnAnomalyScore: 0.9
`)
	s.Require().NoError(err)
	policyFile.Close()

	s.policyEngine, err = policy.NewStaticPolicyEngine(policyFile.Name())
	s.Require().NoError(err)
}

func (s *AIDrivenSecuritySuite) SetupTest() {
	s.tenantRepo = new(repomocks.TenantRepository)
	s.keyRepo = new(repomocks.KeyRepository)
	s.riskRepo = new(repomocks.RiskRepository)
	s.klr = new(servicemocks.KeyLifecycleRegistry)
	s.keyProvider = new(servicemocks.KeyProvider)

	keyProviders := map[string]service.KeyProvider{
		"default": s.keyProvider,
	}

	s.riskOracle = application.NewRiskOracle(s.riskRepo)
	kms, _ := application.NewKeyManagementService(
		keyProviders,
		s.keyRepo,
		s.tenantRepo,
		s.policyEngine,
		s.klr,
		logger.NewNoopLogger(),
		s.riskOracle,
	)
	s.kms = kms
}

func (s *AIDrivenSecuritySuite) TestPolicyTuningFlow() {
	ctx := context.Background()
	tenantID := "tenant-acme"
	tenant := &models.Tenant{TenantID: tenantID, ComplianceClass: "L3"}
	pk, _ := rsa.GenerateKey(rand.Reader, 2048)

	// 1. Low Risk Scenario
	s.Run("LowRiskRotationSucceeds", func() {
		// Setup mocks for low risk
		s.tenantRepo.On("FindByID", ctx, tenantID).Return(tenant, nil).Once()
		s.riskRepo.On("GetTenantRiskProfile", ctx, tenantID).Return(&models.TenantRiskProfile{AnomalyScore: 0.1}, nil).Once()
		s.keyProvider.On("GenerateKey", ctx, mock.Anything).Return("new-kid", "new-ref", &pk.PublicKey, nil).Once()
		s.keyRepo.On("CreateKey", ctx, mock.Anything).Return(nil).Once()
		s.klr.On("LogEvent", ctx, mock.Anything).Return(nil).Once()
		s.keyRepo.On("GetActiveKeys", ctx, tenantID).Return([]*models.Key{}, nil).Once()
		s.keyRepo.On("GetDeprecatedKeys", ctx, tenantID).Return([]*models.Key{}, nil).Once()

		_, err := s.kms.RotateTenantKey(ctx, tenantID, nil)
		s.NoError(err)
	})

	// 2. High Risk Scenario
	s.Run("HighRiskRotationFails", func() {
		// Setup mocks for high risk
		s.tenantRepo.On("FindByID", ctx, tenantID).Return(tenant, nil).Once()
		s.riskRepo.On("GetTenantRiskProfile", ctx, tenantID).Return(&models.TenantRiskProfile{AnomalyScore: 0.95}, nil).Once()

		_, err := s.kms.RotateTenantKey(ctx, tenantID, nil)
		s.Error(err)
		s.Contains(err.Error(), "policy violation: high anomaly score")
	})
}

func TestAIDrivenSecurity(t *testing.T) {
	suite.Run(t, new(AIDrivenSecuritySuite))
}
