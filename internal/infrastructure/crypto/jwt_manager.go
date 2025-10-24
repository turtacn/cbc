package crypto

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

type jwtManagerImpl struct {
	keyManager KeyManager
	log        logger.Logger
}

// NewJWTManager creates a new JWTManager.
func NewJWTManager(keyManager KeyManager, log logger.Logger) service.CryptoService {
	return &jwtManagerImpl{
		keyManager: keyManager,
		log:        log,
	}
}

// GenerateJWT creates and signs a new JWT.
func (j *jwtManagerImpl) GenerateJWT(ctx context.Context, token *models.Token) (string, *errors.AppError) {
	privateKey, keyID, err := j.keyManager.GetPrivateKey(ctx, token.TenantID)
	if err != nil {
		return "", err
	}

	claims := jwt.RegisteredClaims{
		ID:        token.JTI,
		Subject:   token.DeviceID.String(),
		Audience:  token.Audience,
		Issuer:    token.Issuer,
		IssuedAt:  jwt.NewNumericDate(token.IssuedAt),
		ExpiresAt: jwt.NewNumericDate(token.ExpiresAt),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	jwtToken.Header["kid"] = keyID
	jwtToken.Header["tenant_id"] = token.TenantID.String()

	signedString, signErr := jwtToken.SignedString(privateKey)
	if signErr != nil {
		j.log.Error(ctx, "Failed to sign JWT", signErr)
		return "", errors.ErrKMSFailure.WithError(signErr)
	}

	return signedString, nil
}

// VerifyJWT parses and validates a JWT string.
func (j *jwtManagerImpl) VerifyJWT(ctx context.Context, tokenString string, tenantID uuid.UUID) (*jwt.RegisteredClaims, *errors.AppError) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.ErrInvalidToken
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.ErrInvalidToken
		}

		return j.keyManager.GetPublicKey(ctx, tenantID, kid)
	})

	if err != nil {
		// Handle specific JWT errors
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.ErrExpiredToken
		}
		return nil, errors.ErrInvalidToken.WithError(err)
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.ErrInvalidToken
}

// GetPublicKey is part of the CryptoService interface, implemented by KeyManager.
func (j *jwtManagerImpl) GetPublicKey(ctx context.Context, tenantID uuid.UUID, keyID string) (*rsa.PublicKey, *errors.AppError) {
	return j.keyManager.GetPublicKey(ctx, tenantID, keyID)
}

// GetPrivateKey is part of the CryptoService interface, implemented by KeyManager.
func (j *jwtManagerImpl) GetPrivateKey(ctx context.Context, tenantID uuid.UUID) (*rsa.PrivateKey, string, *errors.AppError) {
	return j.keyManager.GetPrivateKey(ctx, tenantID)
}
//Personal.AI order the ending