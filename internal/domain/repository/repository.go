// internal/domain/repository/repository.go
package repository

import "github.com/turtacn/cbc/internal/domain/models"

type UserRepo interface {
   FindByEmail(tenantID, email string) (*models.User, error)
}

type DeviceRepo interface {
   Register(d *models.Device) error
   Find(tenantID, deviceID string) (*models.Device, error)
}

type KeyRepo interface {
   ActiveKey() (*models.KeyMeta, []byte /*privOrSharedKey*/, error)
   FindByKID(kid string) (*models.KeyMeta, []byte, error)
}

type AuditRepo interface {
   Write(event string, payload map[string]any) error
}

type TokenBlacklist interface {
   IsRevoked(jti string) (bool, error)
   Revoke(jti string) error
}
