// Package repository 定义领域仓储接口
// 租户仓储负责租户领域对象的持久化操作
package repository

import (
	"context"
	"time"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/constants"
)

//go:generate mockery --name TenantRepository --output mocks --outpkg mocks
// TenantRepository defines the contract for persistence operations related to the Tenant domain object.
// The implementation can be found at: internal/infrastructure/persistence/postgres/tenant_repo_impl.go
// TenantRepository 定义了租户领域对象的持久化操作契约。
// 实现类位于：internal/infrastructure/persistence/postgres/tenant_repo_impl.go
type TenantRepository interface {
	// Save persists a new tenant's configuration to the data store.
	// Save 保存租户配置到持久化存储。
	Save(ctx context.Context, tenant *models.Tenant) error

	// Update modifies an existing tenant's configuration.
	// Update 更新租户配置。
	Update(ctx context.Context, tenant *models.Tenant) error

	// FindByID retrieves a tenant's configuration by its unique ID.
	// Returns an error if the tenant is not found.
	// FindByID 根据租户 ID 查询租户配置。如果租户不存在则返回错误。
	FindByID(ctx context.Context, tenantID string) (*models.Tenant, error)

	// FindByName retrieves a tenant's configuration by its name.
	// Used for ensuring name uniqueness during registration.
	// FindByName 根据租户名称查询租户配置。用于租户注册时的名称唯一性检查。
	FindByName(ctx context.Context, name string) (*models.Tenant, error)

	// FindAll retrieves a paginated list of all tenants.
	// Used for administrative displays.
	// FindAll 查询所有租户（分页）。用于管理端的租户列表展示。
	FindAll(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error)

	// FindActiveAll retrieves all tenants with an 'active' status.
	// Used for loading tenant configurations at system startup.
	// FindActiveAll 查询所有活跃租户（状态为 active）。用于系统启动时的租户配置加载。
	FindActiveAll(ctx context.Context) ([]*models.Tenant, error)

	// Exists checks for the existence of a tenant by its ID.
	// Used for quick existence checks before registration.
	// Exists 检查租户是否存在。用于租户注册前的快速存在性检查。
	Exists(ctx context.Context, tenantID string) (bool, error)

	// UpdateStatus changes the status of a specific tenant.
	// UpdateStatus 更新租户状态。
	UpdateStatus(ctx context.Context, tenantID string, status constants.TenantStatus) error

	// UpdateRateLimitConfig updates the rate limiting configuration for a tenant.
	// UpdateRateLimitConfig 更新租户的速率限制配置。
	UpdateRateLimitConfig(ctx context.Context, tenantID string, config *models.RateLimitConfig) error

	// UpdateTokenTTLConfig updates the token TTL configuration for a tenant.
	// UpdateTokenTTLConfig 更新租户的令牌 TTL 配置。
	UpdateTokenTTLConfig(ctx context.Context, tenantID string, config *models.TokenTTLConfig) error

	// UpdateKeyRotationPolicy updates the key rotation policy for a tenant.
	// UpdateKeyRotationPolicy 更新租户的密钥轮换策略。
	UpdateKeyRotationPolicy(ctx context.Context, tenantID string, policy *models.KeyRotationPolicy) error

	// Delete performs a soft delete on a tenant, marking it as deleted.
	// Delete 删除租户（软删除）。该方法不会物理删除租户记录，而是标记为 deleted 状态。
	Delete(ctx context.Context, tenantID string) error

	// GetTenantMetrics retrieves statistical metrics for a specific tenant.
	// Used for monitoring and analysis.
	// GetTenantMetrics 获取租户的统计指标。用于监控和分析。
	GetTenantMetrics(ctx context.Context, tenantID string) (*TenantMetrics, error)

	// GetAllMetrics retrieves aggregated statistical metrics for all tenants.
	// Used for system-level monitoring and analysis.
	// GetAllMetrics 获取所有租户的汇总统计指标。用于系统级别的监控和分析。
	GetAllMetrics(ctx context.Context) (*SystemMetrics, error)

	// IncrementRequestCount increases the request counter for a tenant.
	// Used for QPS statistics and quota management.
	// IncrementRequestCount 增加租户的请求计数。用于租户级别的 QPS 统计和配额管理。
	IncrementRequestCount(ctx context.Context, tenantID string, count int64) error

	// UpdateLastActivityAt updates the last activity timestamp for a tenant.
	// Called when any device under the tenant successfully authenticates.
	// UpdateLastActivityAt 更新租户的最后活跃时间。该方法在租户下任意设备认证成功时调用。
	UpdateLastActivityAt(ctx context.Context, tenantID string, lastActivityAt time.Time) error
}

// TenantMetrics holds statistical metrics for a single tenant.
// TenantMetrics 租户统计指标。
type TenantMetrics struct {
	// TenantID is the unique identifier for the tenant.
	// TenantID 是租户的 ID。
	TenantID            string    // 租户 ID
	// TotalDevices is the total number of devices registered to the tenant.
	// TotalDevices 是租户注册的设备总数。
	TotalDevices        int64     // 设备总数
	// ActiveDevices is the number of devices that have been active in the last 24 hours.
	// ActiveDevices 是过去 24 小时内活跃的设备数。
	ActiveDevices       int64     // 活跃设备数（24 小时内）
	// TotalTokensIssued is the total number of tokens issued to the tenant.
	// TotalTokensIssued 是向租户颁发的令牌总数。
	TotalTokensIssued   int64     // 累计颁发令牌数
	// TokensIssuedToday is the number of tokens issued to the tenant today.
	// TokensIssuedToday 是今天向租户颁发的令牌数。
	TokensIssuedToday   int64     // 今日颁发令牌数
	// TotalRequestsToday is the total number of requests made by the tenant today.
	// TotalRequestsToday 是租户今天发出的总请求数。
	TotalRequestsToday  int64     // 今日总请求数
	// SuccessRequestRate is the percentage of successful requests.
	// SuccessRequestRate 是成功请求的百分比。
	SuccessRequestRate  float64   // 请求成功率（%）
	// AverageLatencyMs is the average request latency in milliseconds.
	// AverageLatencyMs 是平均请求延迟（毫秒）。
	AverageLatencyMs    float64   // 平均延迟（毫秒）
	// P95LatencyMs is the 95th percentile request latency in milliseconds.
	// P95LatencyMs 是第 95个百分位的请求延迟（毫秒）。
	P95LatencyMs        float64   // P95 延迟（毫秒）
	// RateLimitHitsToday is the number of times the rate limit has been hit today.
	// RateLimitHitsToday 是今天达到速率限制的次数。
	RateLimitHitsToday  int64     // 今日限流触发次数
	// TokenRevocations is the total number of tokens revoked for the tenant.
	// TokenRevocations 是为租户撤销的令牌总数。
	TokenRevocations    int64     // 累计令牌吊销次数
	// LastActivityAt is the timestamp of the last activity for the tenant.
	// LastActivityAt 是租户最后一次活动的时间戳。
	LastActivityAt      time.Time // 最后活跃时间
	// StorageUsedBytes is the amount of storage used by the tenant in bytes.
	// StorageUsedBytes 是租户使用的存储量（字节）。
	StorageUsedBytes    int64     // 存储使用量（字节）
	// BandwidthUsedBytes is the amount of bandwidth used by the tenant in bytes.
	// BandwidthUsedBytes 是租户使用的带宽量（字节）。
	BandwidthUsedBytes  int64     // 带宽使用量（字节）
	// CurrentMonthlyBill is the current monthly bill for the tenant.
	// CurrentMonthlyBill 是租户的当前月度账单。
	CurrentMonthlyBill  float64   // 当月账单（美元）
}

// SystemMetrics holds aggregated statistical metrics for the entire system.
// SystemMetrics 系统统计指标（所有租户的汇总）。
type SystemMetrics struct {
	// TotalTenants is the total number of tenants in the system.
	// TotalTenants 是系统中的租户总数。
	TotalTenants        int64                        // 租户总数
	// ActiveTenants is the number of tenants that have been active in the last 7 days.
	// ActiveTenants 是过去 7 天内活跃的租户数。
	ActiveTenants       int64                        // 活跃租户数（7 天内）
	// TotalDevices is the total number of devices in the system.
	// TotalDevices 是系统中的设备总数。
	TotalDevices        int64                        // 设备总数
	// ActiveDevices is the number of devices that have been active in the last 24 hours.
	// ActiveDevices 是过去 24 小时内活跃的设备数。
	ActiveDevices       int64                        // 活跃设备数（24 小时内）
	// TotalTokensIssued is the total number of tokens issued in the system.
	// TotalTokensIssued 是系统中颁发的令牌总数。
	TotalTokensIssued   int64                        // 累计颁发令牌数
	// TokensIssuedToday is the number of tokens issued in the system today.
	// TokensIssuedToday 是今天在系统中颁发的令牌数。
	TokensIssuedToday   int64                        // 今日颁发令牌数
	// TotalRequestsToday is the total number of requests made in the system today.
	// TotalRequestsToday 是今天在系统中发出的总请求数。
	TotalRequestsToday  int64                        // 今日总请求数
	// AverageQPS is the average queries per second.
	// AverageQPS 是平均每秒查询次数。
	AverageQPS          float64                      // 平均 QPS
	// PeakQPS is the peak queries per second.
	// PeakQPS 是峰值每秒查询次数。
	PeakQPS             float64                      // 峰值 QPS
	// SuccessRequestRate is the percentage of successful requests.
	// SuccessRequestRate 是成功请求的百分比。
	SuccessRequestRate  float64                      // 请求成功率（%）
	// AverageLatencyMs is the average request latency in milliseconds.
	// AverageLatencyMs 是平均请求延迟（毫秒）。
	AverageLatencyMs    float64                        // 平均延迟（毫秒）
	// P95LatencyMs is the 95th percentile request latency in milliseconds.
	// P95LatencyMs 是第 95个百分位的请求延迟（毫秒）。
	P95LatencyMs        float64                        // P95 延迟（毫秒）
	// P99LatencyMs is the 99th percentile request latency in milliseconds.
	// P99LatencyMs 是第 99个百分位的请求延迟（毫秒）。
	P99LatencyMs        float64                        // P99 延迟（毫秒）
	// RateLimitHitsToday is the number of times the rate limit has been hit today.
	// RateLimitHitsToday 是今天达到速率限制的次数。
	RateLimitHitsToday  int64                          // 今日限流触发次数
	// ByStatus is a map of tenant status to the number of tenants with that status.
	// ByStatus 是租户状态到具有该状态的租户数的映射。
	ByStatus            map[constants.TenantStatus]int64 // 按状态统计租户数
	// StorageUsedGB is the amount of storage used by the system in gigabytes.
	// StorageUsedGB 是系统使用的存储量（GB）。
	StorageUsedGB       float64                        // 存储使用量（GB）
	// BandwidthUsedGB is the amount of bandwidth used by the system in gigabytes.
	// BandwidthUsedGB 是系统使用的带宽量（GB）。
	BandwidthUsedGB     float64                        // 带宽使用量（GB）
	// TotalMonthlyRevenue is the total monthly revenue for the system.
	// TotalMonthlyRevenue 是系统的总月收入。
	TotalMonthlyRevenue float64                        // 当月总收入（美元）
}

// TenantQuery defines parameters for complex tenant searches.
// Used for filtering and sorting in administrative interfaces.
// TenantQuery 租户查询参数。用于复杂查询场景（如管理端的租户列表筛选）。
type TenantQuery struct {
	// TenantID is the tenant ID to filter by.
	// TenantID 是要筛选的租户 ID。
	TenantID         string                // 租户 ID（可选，模糊匹配）
	// Name is the tenant name to filter by.
	// Name 是要筛选的租户名称。
	Name             string                // 租户名称（可选，模糊匹配）
	// Status is the tenant status to filter by.
	// Status 是要筛选的租户状态。
	Status           constants.TenantStatus // 租户状态（可选）
	// CreatedAfter is the start of the creation date range to filter by.
	// CreatedAfter 是要筛选的创建日期范围的开始。
	CreatedAfter     *time.Time            // 创建时间下界（可选）
	// CreatedBefore is the end of the creation date range to filter by.
	// CreatedBefore 是要筛选的创建日期范围的结束。
	CreatedBefore    *time.Time            // 创建时间上界（可选）
	// LastActivityAfter is the start of the last activity date range to filter by.
	// LastActivityAfter 是要筛选的最后活动日期范围的开始。
	LastActivityAfter  *time.Time          // 最后活跃时间下界（可选）
	// LastActivityBefore is the end of the last activity date range to filter by.
	// LastActivityBefore 是要筛选的最后活动日期范围的结束。
	LastActivityBefore *time.Time        // 最后活跃时间上界（可选）
	// MinDevices is the minimum number of devices to filter by.
	// MinDevices 是要筛选的最小设备数。
	MinDevices       int64               // 最小设备数（可选）
	// MaxDevices is the maximum number of devices to filter by.
	// MaxDevices 是要筛选的最大设备数。
	MaxDevices       int64               // 最大设备数（可选）
	// Limit is the maximum number of results to return.
	// Limit 是要返回的最大结果数。
	Limit            int                 // 每页数量（默认 100，最大 1000）
	// Offset is the number of results to skip.
	// Offset 是要跳过的结果数。
	Offset           int                 // 偏移量
	// OrderBy is the field to order the results by.
	// OrderBy 是对结果进行排序的字段。
	OrderBy          string              // 排序字段（如 "created_at DESC"）
}

// FindByQuery is an advanced search method for tenants based on a query object.
// This method is intended for complex filtering scenarios in administrative UIs.
// FindByQuery 根据查询条件查询租户（高级查询接口）。该方法用于管理端的复杂查询场景。
//
// FindByQuery(ctx context.Context, query TenantQuery) ([]*models.Tenant, int64, error)
