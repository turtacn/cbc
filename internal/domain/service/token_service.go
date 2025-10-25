package service

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
)

type TokenService interface {
	IssueTokenPair(ctx context.Context, tenant *models.Tenant, device *models.Device) (*models.Token, *models.Token, *errors.AppError)
	VerifyToken(ctx context.Context, tokenString string) (*models.Token, *errors.AppError)
	RevokeToken(ctx context.Context, jti string) *errors.AppError
	RefreshToken(ctx context.Context, oldRefreshTokenString string) (*models.Token, *models.Token, *errors.AppError)
}

type tokenServiceImpl struct {
	tokenRepo      repository.TokenRepository
	cryptoSvc      CryptoService
	revocationList sync.Map
}

func NewTokenService(tokenRepo repository.TokenRepository, cryptoSvc CryptoService) TokenService {
	return &tokenServiceImpl{
		tokenRepo: tokenRepo,
		cryptoSvc: cryptoSvc,
	}
}

func (s *tokenServiceImpl) IssueTokenPair(ctx context.Context, tenant *models.Tenant, device *models.Device) (*models.Token, *models.Token, *errors.AppError) {
	if tenant == nil || device == nil {
		return nil, nil, errors.ErrInvalidRequest
	}

	deviceID, err := uuid.Parse(device.DeviceID)
	if err != nil {
		return nil, nil, errors.ErrInvalidUUID
	}

	accessToken := models.NewToken(tenant.ID, deviceID, constants.AccessToken, time.Hour, "", nil, "")
	refreshToken := models.NewToken(tenant.ID, deviceID, constants.RefreshToken, 7*24*time.Hour, "", nil, "")

	if signedString, err := s.cryptoSvc.GenerateJWT(ctx, accessToken); err != nil {
		return nil, nil, err
	} else {
		accessToken.SetSignedString(signedString)
	}
	if signedString, err := s.cryptoSvc.GenerateJWT(ctx, refreshToken); err != nil {
		return nil, nil, err
	} else {
		refreshToken.SetSignedString(signedString)
	}

	if err := s.tokenRepo.Save(ctx, accessToken); err != nil {
		return nil, nil, err
	}
	if err := s.tokenRepo.Save(ctx, refreshToken); err != nil {
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}

func (s *tokenServiceImpl) VerifyToken(ctx context.Context, tokenString string) (*models.Token, *errors.AppError) {
	claims, err := s.cryptoSvc.VerifyJWT(ctx, tokenString, uuid.Nil)
	if err != nil {
		return nil, err
	}

	if _, ok := s.revocationList.Load(claims.ID); ok {
		return nil, errors.ErrTokenRevoked
	}

	// In a real implementation, we would fetch the token from the repository
	// to get more details.
	return &models.Token{
		JTI: claims.ID,
	}, nil
}

func (s *tokenServiceImpl) RevokeToken(ctx context.Context, jti string) *errors.AppError {
	s.revocationList.Store(jti, true)
	return nil
}

func (s *tokenServiceImpl) RefreshToken(ctx context.Context, oldRefreshTokenString string) (*models.Token, *models.Token, *errors.AppError) {
	claims, err := s.cryptoSvc.VerifyJWT(ctx, oldRefreshTokenString, uuid.Nil)
	if err != nil {
		return nil, nil, err
	}

	if _, ok := s.revocationList.Load(claims.ID); ok {
		return nil, nil, errors.ErrTokenRevoked
	}

	// In a real implementation, we would fetch the token from the repository
	// and check if it's a valid refresh token.

	if len(claims.Audience) == 0 {
		return nil, nil, errors.ErrInvalidToken
	}

	tenantID, _ := uuid.Parse(claims.Subject)
	deviceID, _ := uuid.Parse(claims.Audience[0])

	// Issue a new token pair
	accessToken := models.NewToken(tenantID, deviceID, constants.AccessToken, time.Hour, "", nil, "")
	refreshToken := models.NewToken(tenantID, deviceID, constants.RefreshToken, 7*24*time.Hour, "", nil, "")

	if signedString, err := s.cryptoSvc.GenerateJWT(ctx, accessToken); err != nil {
		return nil, nil, err
	} else {
		accessToken.SetSignedString(signedString)
	}
	if signedString, err := s.cryptoSvc.GenerateJWT(ctx, refreshToken); err != nil {
		return nil, nil, err
	} else {
		refreshToken.SetSignedString(signedString)
	}

	if err := s.tokenRepo.Save(ctx, accessToken); err != nil {
		return nil, nil, err
	}
	if err := s.tokenRepo.Save(ctx, refreshToken); err != nil {
		return nil, nil, err
	}

	// Revoke the old refresh token
	s.revocationList.Store(claims.ID, true)

	return accessToken, refreshToken, nil
}
