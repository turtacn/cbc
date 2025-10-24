// internal/infrastructure/crypto/jwt_manager_test.go
package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/errors"
)

func TestJWTManager_IssueToken(t *testing.T) {
	// 生成测试用的 RSA 密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &JWTConfig{
		Issuer:        "cbc-auth-service",
		Audience:      []string{"cbc-agents"},
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		SigningMethod: jwt.SigningMethodRS256,
	}

	manager := NewJWTManager(config)
	ctx := context.Background()

	tenantID := uuid.New()
	deviceID := uuid.New()
	jti := uuid.New().String()
	now := time.Now()

	tests := []struct {
		name    string
		token   *models.Token
		wantErr bool
	}{
		{
			name: "Successfully issue access token",
			token: &models.Token{
				ID:        uuid.New(),
				JTI:       jti,
				TenantID:  tenantID,
				DeviceID:  deviceID,
				TokenType: models.TokenTypeAccess,
				Scope:     "agent:read agent:write",
				IssuedAt:  now,
				ExpiresAt: now.Add(15 * time.Minute),
			},
			wantErr: false,
		},
		{
			name: "Successfully issue refresh token",
			token: &models.Token{
				ID:        uuid.New(),
				JTI:       jti,
				TenantID:  tenantID,
				DeviceID:  deviceID,
				TokenType: models.TokenTypeRefresh,
				Scope:     "agent:read agent:write",
				IssuedAt:  now,
				ExpiresAt: now.Add(30 * 24 * time.Hour),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := manager.IssueToken(ctx, tt.token)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, tokenString)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, tokenString)

				// 验证生成的 token
				parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return &privateKey.PublicKey, nil
				})
				require.NoError(t, err)
				assert.True(t, parsedToken.Valid)

				claims, ok := parsedToken.Claims.(jwt.MapClaims)
				require.True(t, ok)

				assert.Equal(t, jti, claims["jti"])
				assert.Equal(t, tenantID.String(), claims["tenant_id"])
				assert.Equal(t, deviceID.String(), claims["device_id"])
				assert.Equal(t, string(tt.token.TokenType), claims["token_type"])
				assert.Equal(t, tt.token.Scope, claims["scope"])
			}
		})
	}
}

func TestJWTManager_ValidateToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &JWTConfig{
		Issuer:        "cbc-auth-service",
		Audience:      []string{"cbc-agents"},
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		SigningMethod: jwt.SigningMethodRS256,
	}

	manager := NewJWTManager(config)
	ctx := context.Background()

	tenantID := uuid.New()
	deviceID := uuid.New()
	jti := uuid.New().String()
	now := time.Now()

	// 创建有效的 token
	validToken := &models.Token{
		ID:        uuid.New(),
		JTI:       jti,
		TenantID:  tenantID,
		DeviceID:  deviceID,
		TokenType: models.TokenTypeAccess,
		Scope:     "agent:read agent:write",
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	}
	validTokenString, err := manager.IssueToken(ctx, validToken)
	require.NoError(t, err)

	// 创建过期的 token
	expiredToken := &models.Token{
		ID:        uuid.New(),
		JTI:       uuid.New().String(),
		TenantID:  tenantID,
		DeviceID:  deviceID,
		TokenType: models.TokenTypeAccess,
		Scope:     "agent:read",
		IssuedAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	expiredTokenString, err := manager.IssueToken(ctx, expiredToken)
	require.NoError(t, err)

	tests := []struct {
		name        string
		tokenString string
		wantErr     bool
		errType     error
	}{
		{
			name:        "Valid token",
			tokenString: validTokenString,
			wantErr:     false,
		},
		{
			name:        "Expired token",
			tokenString: expiredTokenString,
			wantErr:     true,
			errType:     errors.ErrTokenExpired,
		},
		{
			name:        "Invalid token format",
			tokenString: "invalid.token.string",
			wantErr:     true,
			errType:     errors.ErrInvalidToken,
		},
		{
			name:        "Empty token",
			tokenString: "",
			wantErr:     true,
			errType:     errors.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := manager.ValidateToken(ctx, tt.tokenString)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, token)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
				assert.Equal(t, jti, token.JTI)
				assert.Equal(t, tenantID, token.TenantID)
				assert.Equal(t, deviceID, token.DeviceID)
			}
		})
	}
}

func TestJWTManager_RefreshPublicKeys(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &JWTConfig{
		Issuer:        "cbc-auth-service",
		Audience:      []string{"cbc-agents"},
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		SigningMethod: jwt.SigningMethodRS256,
	}

	manager := NewJWTManager(config)
	ctx := context.Background()

	err = manager.RefreshPublicKeys(ctx)
	assert.NoError(t, err)
}
