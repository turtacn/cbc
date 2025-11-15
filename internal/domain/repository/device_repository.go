package repository

import (
	"context"
	"github.com/turtacn/cbc/internal/domain/models"
)

//go:generate mockery --name DeviceRepository --output ./mocks --filename device_repository.go --structname DeviceRepository
// DeviceRepository defines the interface for interacting with the persistence layer for device data.
// It provides a set of methods for creating, retrieving, updating, and listing devices.
// DeviceRepository 定义了与设备数据的持久化层交互的接口。
// 它提供了一组用于创建、检索、更新和列出设备的方法。
type DeviceRepository interface {
	// FindByID retrieves a single device by its unique agent ID.
	// It returns the device if found, otherwise it returns a not found error.
	// FindByID 通过其唯一的代理 ID 检索单个设备。
	// 如果找到则返回设备，否则返回未找到错误。
	FindByID(ctx context.Context, agentID string) (*models.Device, error)

	// Save persists a new device to the data store.
	// Save 将新设备持久化到数据存储中。
	Save(ctx context.Context, device *models.Device) error

	// Update modifies the details of an existing device in the data store.
	// Update 修改数据存储中现有设备的详细信息。
	Update(ctx context.Context, device *models.Device) error

	// FindByTenantID retrieves a paginated list of devices belonging to a specific tenant.
	// It also returns the total count of devices for that tenant to aid in pagination.
	// FindByTenantID 检索属于特定租户的设备的分页列表。
	// 它还返回该租户的设备总数以帮助分页。
	FindByTenantID(ctx context.Context, tenantID string, page, pageSize int) ([]*models.Device, int64, error)
}
