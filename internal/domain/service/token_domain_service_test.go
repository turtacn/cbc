package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
)

// MockTokenRepository is a mock implementation of TokenRepository
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) Save(ctx context.Context, token *models.Token) *errors.AppError {
	args := m.Called(ctx, token)
	return args.Get(0).(*errors.AppError)
}
// ... other methods would be mocked here

// MockCryptoService is a mock implementation of CryptoService
type MockCryptoService struct {
	mock.Mock
}

func (m *MockCryptoService) GenerateJWT(ctx context.Context, token *models.Token) (string, *errors.AppError) {
	args := m.Called(ctx, token)
	return args.String(0), args.Get(1).(*errors.AppError)
}
// ... other methods would be mocked here

func TestTokenDomainService_IssueTokenPair(t *testing.T) {
	mockTokenRepo := new(MockTokenRepository)
	mockCryptoSvc := new(MockCryptoService)

	// Setup expectations
	mockTokenRepo.On("Save", mock.Anything, mock.Anything).Return(nil)
	mockCryptoSvc.On("GenerateJWT", mock.Anything, mock.Anything).Return("signed-jwt-string", nil)

	tokenService := service.NewTokenService(mockTokenRepo, mockCryptoSvc, nil) // Real implementation would take logger

	tenant := &models.Tenant{}
	device := &models.Device{}

	accessToken, refreshToken, err := tokenService.IssueTokenPair(context.Background(), tenant, device)

	assert.NoError(t, err)
	assert.NotNil(t, accessToken)
	assert.NotNil(t, refreshToken)

	mockTokenRepo.AssertExpectations(t)
	mockCryptoSvc.AssertExpectations(t)
}
//Personal.AI order the ending