package repository

import (
	"context"

	"github.com/turtacn/cbc/internal/domain/models"
)

//go:generate mockery --name KeyRepository --output mocks --outpkg mocks
// KeyRepository defines the interface for the persistence of cryptographic key metadata.
// It provides methods for creating, retrieving, and updating the lifecycle status of keys.
// KeyRepository 定义了加密密钥元数据持久化的接口。
// 它提供了创建、检索和更新密钥生命周期状态的方法。
type KeyRepository interface {
	// CreateKey saves the metadata of a new cryptographic key.
	// CreateKey 保存新加密密钥的元数据。
	CreateKey(ctx context.Context, key *models.Key) error

	// GetKeyByKID retrieves the metadata of a specific key by its Key ID (kid) for a given tenant.
	// GetKeyByKID 通过给定租户的密钥 ID (kid) 检索特定密钥的元数据。
	GetKeyByKID(ctx context.Context, tenantID, kid string) (*models.Key, error)

	// GetActiveKeys retrieves all keys with an 'active' status for a given tenant.
	// These keys can be used for new signing operations.
	// GetActiveKeys 检索给定租户的所有状态为“活动”的密钥。
	// 这些密钥可用于新的签名操作。
	GetActiveKeys(ctx context.Context, tenantID string) ([]*models.Key, error)

	// GetDeprecatedKeys retrieves all keys with a 'deprecated' status for a given tenant.
	// These keys should only be used for verifying old signatures, not for creating new ones.
	// GetDeprecatedKeys 检索给定租户的所有状态为“已弃用”的密钥。
	// 这些密钥只应用于验证旧签名，不应用于创建新签名。
	GetDeprecatedKeys(ctx context.Context, tenantID string) ([]*models.Key, error)

	// UpdateKeyStatus changes the lifecycle status of a specific key (e.g., from 'active' to 'deprecated').
	// UpdateKeyStatus 更改特定密钥的生命周期状态（例如，从“活动”到“已弃用”）。
	UpdateKeyStatus(ctx context.Context, tenantID, kid, status string) error
}
