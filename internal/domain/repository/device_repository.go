// Package repository 定义领域仓储接口
// 设备仓储负责设备领域对象的持久化操作
package repository

import (
	"context"
	"time"

	"github.com/turtacn/cbc/internal/domain/models"
)

// DeviceRepository 定义设备仓储接口
// 该接口定义了设备领域对象的持久化操作契约
// 实现类：internal/infrastructure/persistence/postgres/device_repo_impl.go
type DeviceRepository interface {
	// Save 保存设备元数据到持久化存储
	// 参数：
	//   - ctx: 请求上下文，用于超时控制和链路追踪
	//   - device: 设备领域模型
	// 返回：
	//   - error: 保存失败时返回错误（如主键冲突、数据库连接失败等）
	Save(ctx context.Context, device *models.Device) error

	// Update 更新设备元数据
	// 参数：
	//   - ctx: 请求上下文
	//   - device: 设备领域模型（包含更新后的字段）
	// 返回：
	//   - error: 更新失败时返回错误（如设备不存在）
	Update(ctx context.Context, device *models.Device) error

	// FindByID 根据设备 ID 查询设备
	// 参数：
	//   - ctx: 请求上下文
	//   - agentID: 终端 Agent 唯一标识符
	// 返回：
	//   - *models.Device: 查询到的设备对象
	//   - error: 查询失败或设备不存在时返回错误（ErrDeviceNotFound）
	FindByID(ctx context.Context, agentID string) (*models.Device, error)

	// FindByTenantID 根据租户 ID 查询所有设备（分页）
	// 用于租户级别的设备管理
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - limit: 每页数量
	//   - offset: 偏移量
	// 返回：
	//   - []*models.Device: 设备切片
	//   - int64: 总记录数
	//   - error: 查询失败时返回错误
	FindByTenantID(ctx context.Context, tenantID string, limit, offset int) ([]*models.Device, int64, error)

	// FindByFingerprint 根据设备指纹查询设备
	// 用于设备注册时的冲突检测（防止设备指纹伪造）
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - fingerprint: 设备指纹哈希值
	// 返回：
	//   - *models.Device: 查询到的设备对象
	//   - error: 查询失败或设备不存在时返回错误（ErrDeviceNotFound）
	FindByFingerprint(ctx context.Context, tenantID, fingerprint string) (*models.Device, error)

	// Exists 检查设备是否存在
	// 用于设备注册前的快速存在性检查
	// 参数：
	//   - ctx: 请求上下文
	//   - agentID: 终端 Agent 唯一标识符
	// 返回：
	//   - bool: true 表示设备存在，false 表示不存在
	//   - error: 查询失败时返回错误
	Exists(ctx context.Context, agentID string) (bool, error)

	// UpdateLastSeen 更新设备的最后活跃时间
	// 该方法在设备每次成功认证时调用
	// 参数：
	//   - ctx: 请求上下文
	//   - agentID: 终端 Agent 唯一标识符
	//   - lastSeenAt: 最后活跃时间
	// 返回：
	//   - error: 更新失败时返回错误
	UpdateLastSeen(ctx context.Context, agentID string, lastSeenAt time.Time) error

	// UpdateTrustLevel 更新设备的信任等级
	// 该方法在设备信任评估后调用
	// 参数：
	//   - ctx: 请求上下文
	//   - agentID: 终端 Agent 唯一标识符
	//   - trustLevel: 新的信任等级
	// 返回：
	//   - error: 更新失败时返回错误
	UpdateTrustLevel(ctx context.Context, agentID string, trustLevel models.TrustLevel) error

	// UpdateStatus 更新设备状态
	// 参数：
	//   - ctx: 请求上下文
	//   - agentID: 终端 Agent 唯一标识符
	//   - status: 新的设备状态
	// 返回：
	//   - error: 更新失败时返回错误
	UpdateStatus(ctx context.Context, agentID string, status models.DeviceStatus) error

	// Delete 删除设备（软删除）
	// 该方法不会物理删除设备记录，而是标记为 deleted 状态
	// 参数：
	//   - ctx: 请求上下文
	//   - agentID: 终端 Agent 唯一标识符
	// 返回：
	//   - error: 删除失败时返回错误
	Delete(ctx context.Context, agentID string) error

	// CountByTenantID 统计租户的设备总数
	// 用于租户级别的设备配额管理
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	// 返回：
	//   - int64: 设备总数
	//   - error: 统计失败时返回错误
	CountByTenantID(ctx context.Context, tenantID string) (int64, error)

	// CountActiveByTenantID 统计租户的活跃设备数
	// 活跃设备定义：最近 24 小时内有活动的设备
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	// 返回：
	//   - int64: 活跃设备数
	//   - error: 统计失败时返回错误
	CountActiveByTenantID(ctx context.Context, tenantID string) (int64, error)

	// FindInactiveDevices 查询长时间未活跃的设备
	// 用于设备自动清理策略
	// 参数：
	//   - ctx: 请求上下文
	//   - inactiveSince: 未活跃时间阈值（如 90 天前）
	//   - limit: 每页数量
	//   - offset: 偏移量
	// 返回：
	//   - []*models.Device: 未活跃设备切片
	//   - int64: 总记录数
	//   - error: 查询失败时返回错误
	FindInactiveDevices(ctx context.Context, inactiveSince time.Time, limit, offset int) ([]*models.Device, int64, error)

	// FindByTrustLevel 根据信任等级查询设备
	// 用于安全审计和风险评估
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - trustLevel: 信任等级
	//   - limit: 每页数量
	//   - offset: 偏移量
	// 返回：
	//   - []*models.Device: 设备切片
	//   - int64: 总记录数
	//   - error: 查询失败时返回错误
	FindByTrustLevel(ctx context.Context, tenantID string, trustLevel models.TrustLevel, limit, offset int) ([]*models.Device, int64, error)

	// BatchUpdateLastSeen 批量更新设备的最后活跃时间
	// 用于性能优化场景（如批量设备心跳上报）
	// 参数：
	//   - ctx: 请求上下文
	//   - updates: map[agentID]lastSeenAt
	// 返回：
	//   - error: 更新失败时返回错误
	BatchUpdateLastSeen(ctx context.Context, updates map[string]time.Time) error

	// GetDeviceMetrics 获取设备的统计指标
	// 用于监控和分析
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	// 返回：
	//   - *DeviceMetrics: 设备统计指标
	//   - error: 查询失败时返回错误
	GetDeviceMetrics(ctx context.Context, tenantID string) (*DeviceMetrics, error)
}

// DeviceMetrics 设备统计指标
type DeviceMetrics struct {
	TotalDevices        int64                         // 设备总数
	ActiveDevices       int64                         // 活跃设备数（24 小时内）
	InactiveDevices     int64                         // 未活跃设备数（> 30 天）
	ByStatus            map[models.DeviceStatus]int64 // 按状态统计
	ByTrustLevel        map[models.TrustLevel]int64   // 按信任等级统计
	NewDevicesToday     int64                         // 今日新增设备数
	NewDevicesThisWeek  int64                         // 本周新增设备数
	NewDevicesThisMonth int64                         // 本月新增设备数
}

// DeviceQuery 设备查询参数
// 用于复杂查询场景（如管理端的设备列表筛选）
type DeviceQuery struct {
	TenantID       string              // 租户 ID（必填）
	AgentID        string              // Agent ID（可选，模糊匹配）
	Status         models.DeviceStatus // 设备状态（可选）
	TrustLevel     models.TrustLevel   // 信任等级（可选）
	Platform       string              // 平台类型（可选）
	LastSeenAfter  *time.Time          // 最后活跃时间下界（可选）
	LastSeenBefore *time.Time          // 最后活跃时间上界（可选）
	CreatedAfter   *time.Time          // 创建时间下界（可选）
	CreatedBefore  *time.Time          // 创建时间上界（可选）
	Limit          int                 // 每页数量（默认 100，最大 1000）
	Offset         int                 // 偏移量
	OrderBy        string              // 排序字段（如 "last_seen_at DESC"）
}

// FindByQuery 根据查询条件查询设备（高级查询接口）
// 该方法用于管理端的复杂查询场景
// 参数：
//   - ctx: 请求上下文
//   - query: 查询参数
//
// 返回：
//   - []*models.Device: 设备切片
//   - int64: 总记录数
//   - error: 查询失败时返回错误
//
// FindByQuery(ctx context.Context, query DeviceQuery) ([]*models.Device, int64, error)

//Personal.AI order the ending
