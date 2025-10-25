package utils

import (
	"encoding/json"
	"time"

	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/models"
)

// TokenToDTO converts a token domain model to a TokenResponse DTO.
func TokenToDTO(token *models.Token) *dto.TokenResponse {
	if token == nil {
		return nil
	}
	return &dto.TokenResponse{
		JTI:       token.JTI,
		TokenType: string(token.TokenType),
		ExpiresIn: int64(time.Until(token.ExpiresAt).Seconds()),
	}
}

// TokenPairToDTO converts access and refresh tokens to a TokenPairResponse DTO.
func TokenPairToDTO(accessToken, refreshToken *models.Token, accessTokenString, refreshTokenString string) *dto.TokenPairResponse {
	return &dto.TokenPairResponse{
		AccessToken:           accessTokenString,
		RefreshToken:          refreshTokenString,
		AccessTokenExpiresIn:  int64(time.Until(accessToken.ExpiresAt).Seconds()),
		RefreshTokenExpiresIn: int64(time.Until(refreshToken.ExpiresAt).Seconds()),
		TokenType:             "Bearer",
	}
}

// DeviceToDTO converts a device domain model to a DeviceResponse DTO.
func DeviceToDTO(device *models.Device) *dto.DeviceResponse {
	if device == nil {
		return nil
	}
	return &dto.DeviceResponse{
		DeviceID:     device.DeviceID,
		TenantID:     device.TenantID,
		DeviceType:   device.DeviceType,
		OS:           device.OS,
		AppVersion:   device.AppVersion,
		RegisteredAt: device.RegisteredAt,
		LastSeenAt:   device.LastSeenAt,
	}
}

// RegisterRequestToDeviceModel converts a registration DTO to a device domain model.
func RegisterRequestToDeviceModel(req *dto.DeviceRegisterRequest) *models.Device {
	return &models.Device{
		DeviceID:   req.DeviceID,
		TenantID:   req.TenantID,
		DeviceType: req.DeviceType,
		OS:         req.OS,
		AppVersion: req.AppVersion,
	}
}

// ToJSONString converts an interface to a JSON string.
// Returns an empty string if marshalling fails.
func ToJSONString(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// TimeToUnixPtr returns a pointer to a Unix timestamp from a time.Time.
// Returns nil if the time is zero.
func TimeToUnixPtr(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	unixTime := t.Unix()
	return &unixTime
}

//Personal.AI order the ending
