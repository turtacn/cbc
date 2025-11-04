package service

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/internal/domain/models"
)

// CryptoService defines the interface for cryptographic operations.
type CryptoService interface {
	EncryptSensitiveData(ctx context.Context, data []byte) ([]byte, error)
	DecryptSensitiveData(ctx context.Context, data []byte) ([]byte, error)
	GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (tokenString string, keyID string, err error)
	VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error)
	GetPublicKey(ctx context.Context, tenantID string, keyID string) (*rsa.PublicKey, error)
	GetPrivateKey(ctx context.Context, tenantID string) (*rsa.PrivateKey, string, error)
	RotateKey(ctx context.Context, tenantID string) (string, error)
}

// RateLimitDimension defines the logical type of rate limiting.
type RateLimitDimension string

const (
	RateLimitDimensionTenant RateLimitDimension = "tenant"
	RateLimitDimensionUser   RateLimitDimension = "user"
	RateLimitDimensionToken  RateLimitDimension = "token"
	RateLimitDimensionDevice RateLimitDimension = "device"
	RateLimitDimensionIP     RateLimitDimension = "ip"
	RateLimitDimensionGlobal RateLimitDimension = "global"
)

// RateLimitService defines the interface for rate limiting operations.
type RateLimitService interface {
	Allow(
		ctx context.Context,
		dimension RateLimitDimension,
		key string,
		identifier string,
	) (allowed bool, remaining int, resetAt time.Time, err error)
}

// TokenBlacklistStore defines the interface for token blacklist operations.
type TokenBlacklistStore interface {
	Revoke(ctx context.Context, tenantID, jti string, exp time.Time) error
	IsRevoked(ctx context.Context, tenantID, jti string) (bool, error)
}

// AuditService defines the interface for logging security audit events.
type AuditService interface {
	LogEvent(ctx context.Context, event models.AuditEvent) error
}

// DeviceAuthStore defines the interface for storing and managing device authorization sessions.
type DeviceAuthStore interface {
	CreateSession(ctx context.Context, session *models.DeviceAuthSession) error
	GetSessionByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceAuthSession, error)
	GetSessionByUserCode(ctx context.Context, userCode string) (*models.DeviceAuthSession, error)
	ApproveSession(ctx context.Context, userCode, tenantID, subject string) error
	DenySession(ctx context.Context, userCode string) error
	TouchPoll(ctx context.Context, deviceCode string) error
}
