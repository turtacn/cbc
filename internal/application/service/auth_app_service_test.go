package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	app_svc "github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.comcom/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/errors"
)

// MockTokenDomainService is a mock of TokenService
type MockTokenDomainService struct {
	mock.Mock
}
func (m *MockTokenDomainService) IssueTokenPair(ctx context.Context, t *models.Tenant, d *models.Device) (*models.Token, *models.Token, *errors.AppError) {
	args := m.Called(ctx, t, d)
	return args.Get(0).(*models.Token), args.Get(1).(*models.Token), args.Get(2).(*errors.AppError)
}
// ... other methods mocked here

// MockTenantRepository is a mock of TenantRepository
type MockTenantRepository struct {
	mock.Mock
}
func (m *MockTenantRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.Tenant, *errors.AppError) {
	args := m.Called(ctx, id)
	return args.Get(0).(*models.Tenant), args.Get(1).(*errors.AppError)
}
// ... other methods mocked here


func TestAuthAppService_IssueToken(t *testing.T) {
	mockTokenSvc := new(MockTokenDomainService)
	mockTenantRepo := new(MockTenantRepository)
	// ... mock other repos and services

	appService := app_svc.NewAuthAppService(mockTokenSvc, nil, mockTenantRepo, nil, nil) // Real implementation would pass all dependencies

	req := &dto.TokenIssueRequest{
		TenantID: uuid.New(),
		DeviceID: "test-device",
		GrantType: "client_credentials",
	}

	// Setup expectations
	mockTenantRepo.On("FindByID", mock.Anything, req.TenantID).Return(&models.Tenant{Status: "active"}, nil)
	mockTokenSvc.On("IssueTokenPair", mock.Anything, mock.Anything, mock.Anything).Return(&models.Token{}, &models.Token{}, nil)
	// ... other expectations

	resp, err := appService.IssueToken(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	mockTenantRepo.AssertExpectations(t)
	mockTokenSvc.AssertExpectations(t)
}
//Personal.AI order the ending