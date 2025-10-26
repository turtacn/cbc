// internal/domain/models/models.go
package models

import "time"

type User struct {
   ID        string
   TenantID  string
   Email     string
   CreatedAt time.Time
}

type Device struct {
   ID        string
   TenantID  string
   UserID    string
   Fingerprint string // 预留TPM/TEE资料
   CreatedAt time.Time
}

type KeyMeta struct {
   KID       string
   Alg       string // HS256/RS256
   PublicPEM string // 对称时为空
   CreatedAt time.Time
   Active    bool
   Canary    bool
}

type TokenClaims struct {
   JTI      string
   Sub      string // user id
   TenantID string
   DeviceID string
   Scope    []string
   Typ      string // access/refresh
   Exp      int64
   Iat      int64
   KID      string
}

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
