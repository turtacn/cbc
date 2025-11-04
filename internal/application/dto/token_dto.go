package dto

import (
	"time"
)

// TokenIssueRequest 令牌颁发请求 DTO
type TokenIssueRequest struct {
	GrantType    string `json:"grant_type" validate:"required,oneof=refresh_token device_credential"`
	RefreshToken string `json:"refresh_token" validate:"required_if=GrantType refresh_token"`
	ClientID     string `json:"client_id" validate:"required_if=GrantType device_credential"`
	ClientSecret string `json:"client_secret" validate:"required_if=GrantType device_credential"`
	TenantID     string `json:"tenant_id" validate:"required,min=1,max=64"`
	AgentID      string `json:"agent_id" validate:"omitempty,min=1,max=128"`
	Scope        string `json:"scope" validate:"omitempty"`
	DeviceInfo   string `json:"device_info" validate:"omitempty"`
	DeviceCode   string `json:"device_code,omitempty"`
}

// TokenRefreshRequest 令牌刷新请求 DTO
type TokenRefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required,min=1"`
	TenantID     string `json:"tenant_id" validate:"required,min=1,max=64"`
	Scope        string `json:"scope" validate:"omitempty"`
}

// TokenRevokeRequest 令牌吊销请求 DTO
type TokenRevokeRequest struct {
	Token         string `json:"token" validate:"required,min=1"`
	TokenTypeHint string `json:"token_type_hint" validate:"omitempty,oneof=refresh_token access_token"`
	TenantID      string `json:"tenant_id" validate:"required,min=1,max=64"`
	Reason        string `json:"reason" validate:"omitempty,max=256"`
}

// DeviceRegisterRequest 设备注册请求 DTO（用于 MGR 代理注册）
type DeviceRegisterRequest struct {
	ClientID           string `json:"client_id" validate:"required,min=1,max=128"`
	ClientAssertionType string `json:"client_assertion_type" validate:"required,eq=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`
	ClientAssertion    string `json:"client_assertion" validate:"required,min=1"`
	GrantType          string `json:"grant_type" validate:"required,eq=client_credentials"`
	TenantID           string `json:"tenant_id" validate:"required,min=1,max=64"`
	AgentID            string `json:"agent_id" validate:"required,min=1,max=128"`
	DeviceFingerprint  string `json:"device_fingerprint" validate:"omitempty,min=1,max=128"`
	DeviceName         string `json:"device_name" validate:"omitempty,max=256"`
	DeviceType         string `json:"device_type" validate:"omitempty,max=64"`
	IPAddress          string `json:"ip_address" validate:"omitempty,ip"`
	UserAgent          string `json:"user_agent" validate:"omitempty,max=512"`
}

// TokenResponse 令牌响应 DTO（单个令牌）
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IssuedAt     int64  `json:"issued_at"`
}

// TokenPairResponse 令牌对响应 DTO（包含 Access Token 和 Refresh Token）
type TokenPairResponse struct {
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	TokenType     string `json:"token_type"`
	ExpiresIn     int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	Scope         string `json:"scope"`
	IssuedAt      int64  `json:"issued_at"`
}

// TokenIntrospectRequest 令牌内省请求 DTO
type TokenIntrospectRequest struct {
	Token         string `json:"token" validate:"required,min=1"`
	TokenTypeHint string `json:"token_type_hint" validate:"omitempty,oneof=access_token refresh_token"`
	TenantID      string `json:"tenant_id" validate:"omitempty,min=1,max=64"`
}

// TokenIntrospectResponse 令牌内省响应 DTO
type TokenIntrospectResponse struct {
	Active            bool     `json:"active"`
	Scope             string   `json:"scope,omitempty"`
	ClientID          string   `json:"client_id,omitempty"`
	TenantID          string   `json:"tenant_id,omitempty"`
	AgentID           string   `json:"agent_id,omitempty"`
	TokenType         string   `json:"token_type,omitempty"`
	Exp               int64    `json:"exp,omitempty"`
	Iat               int64    `json:"iat,omitempty"`
	Nbf               int64    `json:"nbf,omitempty"`
	Sub               string   `json:"sub,omitempty"`
	Aud               []string `json:"aud,omitempty"`
	Iss               string   `json:"iss,omitempty"`
	Jti               string   `json:"jti,omitempty"`
	DeviceTrustLevel  string   `json:"device_trust_level,omitempty"`
}

// TokenRevokeResponse 令牌吊销响应 DTO
type TokenRevokeResponse struct {
	Revoked   bool      `json:"revoked"`
	JTI       string    `json:"jti"`
	RevokedAt time.Time `json:"revoked_at"`
	Message   string    `json:"message,omitempty"`
}

// PublicKeyResponse 公钥响应 DTO
type PublicKeyResponse struct {
	TenantID string      `json:"tenant_id"`
	Keys     []JWKKeyDTO `json:"keys"`
}

// JWKKeyDTO JSON Web Key DTO
type JWKKeyDTO struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Alg string   `json:"alg"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c,omitempty"`
}

// NewTokenResponse 创建令牌响应
func NewTokenResponse(accessToken string, expiresIn int64, scope string) *TokenResponse {
	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       scope,
		IssuedAt:    time.Now().Unix(),
	}
}

// NewTokenPairResponse 创建令牌对响应
func NewTokenPairResponse(accessToken, refreshToken string, accessExpiresIn, refreshExpiresIn int64, scope string) *TokenPairResponse {
	return &TokenPairResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		TokenType:        "Bearer",
		ExpiresIn:        accessExpiresIn,
		RefreshExpiresIn: refreshExpiresIn,
		Scope:            scope,
		IssuedAt:         time.Now().Unix(),
	}
}

// WithRefreshToken 添加刷新令牌到令牌响应
func (r *TokenResponse) WithRefreshToken(refreshToken string) *TokenResponse {
	r.RefreshToken = refreshToken
	return r
}
