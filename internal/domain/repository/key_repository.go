package repository

import (
	"context"

	"github.com/turtacn/cbc/internal/domain/models"
)

// KeyRepository defines the interface for key persistence.
type KeyRepository interface {
	CreateKey(ctx context.Context, key *models.Key) error
	GetKeyByKID(ctx context.Context, tenantID, kid string) (*models.Key, error)
	GetActiveKeys(ctx context.Context, tenantID string) ([]*models.Key, error)
	GetDeprecatedKeys(ctx context.Context, tenantID string) ([]*models.Key, error)
	UpdateKeyStatus(ctx context.Context, tenantID, kid, status string) error
}
