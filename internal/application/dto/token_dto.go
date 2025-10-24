package dto

import "github.com/google/uuid"

// TokenIssueRequest represents the request to issue a new token pair.
// This is typically used during the initial device registration/authentication.
type TokenIssueRequest struct {
	GrantType string    `json:"grant_type" validate:"required,oneof=client_credentials"`
	TenantID  uuid.UUID `json:"tenant_id" validate:"required,uuid"`
	DeviceID  string    `json:"device_id" validate:"required"`
	// MGR client assertion would also be part of a more complete implementation
}

// TokenRefreshRequest represents the request to refresh an access token.
type TokenRefreshRequest struct {
	GrantType    string `json:"grant_type" validate:"required,oneof=refresh_token"`
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// TokenRevokeRequest represents the request to revoke a token.
type TokenRevokeRequest struct {
	Token         string `json:"token" validate:"required"`
	TokenTypeHint string `json:"token_type_hint,omitempty" validate:"omitempty,oneof=access_token refresh_token"`
}

// TokenResponse represents a single token in the API response.
type TokenResponse struct {
	JTI       string `json:"jti"`
	TokenType string `json:"token_type"`
	ExpiresIn int64  `json:"expires_in"`
}

// TokenPairResponse represents the successful response for a token issuance or refresh.
type TokenPairResponse struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	AccessTokenExpiresIn  int64  `json:"access_token_expires_in"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
	TokenType             string `json:"token_type"` // e.g., "Bearer"
}
//Personal.AI order the ending