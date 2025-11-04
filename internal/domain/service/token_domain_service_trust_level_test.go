
package service

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/logger"
)

func TestTokenDomainService_GenerateAccessToken_WithTrustLevel(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	mockCrypto := new(MockCryptoService)
	service := NewTokenDomainService(mockRepo, mockCrypto, logger.NewDefaultLogger())

	ctx := context.Background()
	tenantID := "test-tenant"
	deviceID := "test-device"
	trustLevel := "medium"

	refreshToken := &models.Token{
		TenantID: tenantID,
		DeviceID: deviceID,
		Metadata: map[string]interface{}{
			"device_trust_level": trustLevel,
		},
	}

	mockCrypto.On("GenerateJWT", ctx, tenantID, mock.MatchedBy(func(claims jwt.MapClaims) bool {
		return claims["device_trust_level"] == trustLevel
	})).Return("new-access-token", "new-key-id", nil).Once()

	accessToken, err := service.GenerateAccessToken(ctx, refreshToken, nil)

	assert.NoError(t, err)
	assert.NotNil(t, accessToken)
	mockCrypto.AssertExpectations(t)
}
