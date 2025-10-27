// Package dto provides data transfer objects for the application layer.
package dto

// TenantConfigResponse represents the response for a tenant's configuration.
type TenantConfigResponse struct {
	TenantID          string `json:"tenant_id"`
	AccessTokenTTL    int    `json:"access_token_ttl"`
	RefreshTokenTTL   int    `json:"refresh_token_ttl"`
	MaxActiveSessions int    `json:"max_active_sessions"`
}

// UpdateTenantConfigRequest represents the request to update a tenant's configuration.
type UpdateTenantConfigRequest struct {
	AccessTokenTTL    *int `json:"access_token_ttl,omitempty"`
	RefreshTokenTTL   *int `json:"refresh_token_ttl,omitempty"`
	MaxActiveSessions *int `json:"max_active_sessions,omitempty"`
}

// KeyRotationResponse represents the response for a key rotation request.
type KeyRotationResponse struct {
	NewKeyID  string `json:"new_key_id"`
	OldKeyID  string `json:"old_key_id"`
	Message   string `json:"message"`
}

// ListTenantsRequest represents the request to list tenants.
type ListTenantsRequest struct {
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	Filter   string `json:"filter"`
}

// ListTenantsResponse represents the response for a list tenants request.
type ListTenantsResponse struct {
	Tenants    []TenantInfo `json:"tenants"`
	TotalCount int          `json:"total_count"`
}

// TenantInfo represents a single tenant in a list.
type TenantInfo struct {
	TenantID   string `json:"tenant_id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
}

// CreateTenantRequest represents the request to create a new tenant.
type CreateTenantRequest struct {
	Name            string `json:"name"`
	OwnerEmail      string `json:"owner_email"`
	InitialAdminUser string `json:"initial_admin_user"`
}

// KeyRotationHistory represents the history of key rotations for a tenant.
type KeyRotationHistory struct {
	KeyID      string `json:"key_id"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
	Status     string `json:"status"`
}
