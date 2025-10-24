// Package repository 定义领域仓储接口
// 租户仓储负责租户领域对象的持久化操作
package repository

import (
	"context"
	"time"

	"github.com/turtacn/cbc/internal/domain/models"
)

// TenantRepository 定义租户仓储接口
// 该接口定义了租户领域对象的持久化操作契约
// 实现类：internal/infrastructure/persistence/postgres/tenant_repo_impl.go
type TenantRepository interface {
	// Save 保存租户配置到持久化存储
	// 参数：
	//   - ctx: 请求上下文，用于超时控制和链路追踪
	//   - tenant: 租户领域模型
	// 返回：
	//   - error: 保存失败时返回错误（如主键冲突、数据库连接失败等）
	Save(ctx context.Context, tenant *models.Tenant) error

	// Update 更新租户配置
	// 参数：
	//   - ctx: 请求上下文
	//   - tenant: 租户领域模型（包含更新后的字段）
	// 返回：
	//   - error: 更新失败时返回错误（如租户不存在）
	Update(ctx context.Context, tenant *models.Tenant) error

	// FindByID 根据租户 ID 查询租户配置
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	// 返回：
	//   - *models.Tenant: 查询到的租户对象
	//   - error: 查询失败或租户不存在时返回错误（ErrTenantNotFound）
	FindByID(ctx context.Context, tenantID string) (*models.Tenant, error)

	// FindByName 根据租户名称查询租户配置
	// 用于租户注册时的名称唯一性检查
	// 参数：
	//   - ctx: 请求上下文
	//   - name: 租户名称
	// 返回：
	//   - *models.Tenant: 查询到的租户对象
	//   - error: 查询失败或租户不存在时返回错误（ErrTenantNotFound）
	FindByName(ctx context.Context, name string) (*models.Tenant, error)

	// FindAll 查询所有租户（分页）
	// 用于管理端的租户列表展示
	// 参数：
	//   - ctx: 请求上下文
	//   - limit: 每页数量
	//   - offset: 偏移量
	// 返回：
	//   - []*models.Tenant: 租户切片
	//   - int64: 总记录数
	//   - error: 查询失败时返回错误
	FindAll(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error)

	// FindActiveAll 查询所有活跃租户（状态为 active）
	// 用于系统启动时的租户配置加载
	// 参数：
	//   - ctx: 请求上下文
	// 返回：
	//   - []*models.Tenant: 活跃租户切片
	//   - error: 查询失败时返回错误
	FindActiveAll(ctx context.Context) ([]*models.Tenant, error)

	// Exists 检查租户是否存在
	// 用于租户注册前的快速存在性检查
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	// 返回：
	//   - bool: true 表示租户存在，false 表示不存在
	//   - error: 查询失败时返回错误
	Exists(ctx context.Context, tenantID string) (bool, error)

	// UpdateStatus 更新租户状态
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - status: 新的租户状态
	// 返回：
	//   - error: 更新失败时返回错误
	UpdateStatus(ctx context.Context, tenantID string, status models.TenantStatus) error

	// UpdateRateLimitConfig 更新租户的速率限制配置
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - config: 新的速率限制配置
	// 返回：
	//   - error: 更新失败时返回错误
	UpdateRateLimitConfig(ctx context.Context, tenantID string, config *models.RateLimitConfig) error

	// UpdateTokenTTLConfig 更新租户的令牌 TTL 配置
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - config: 新的令牌 TTL 配置
	// 返回：
	//   - error: 更新失败时返回错误
	UpdateTokenTTLConfig(ctx context.Context, tenantID string, config *models.TokenTTLConfig) error

	// UpdateKeyRotationPolicy 更新租户的密钥轮换策略
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - policy: 新的密钥轮换策略
	// 返回：
	//   - error: 更新失败时返回错误
	UpdateKeyRotationPolicy(ctx context.Context, tenantID string, policy *models.KeyRotationPolicy) error

	// Delete 删除租户（软删除）
	// 该方法不会物理删除租户记录，而是标记为 deleted 状态
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	// 返回：
	//   - error: 删除失败时返回错误
	Delete(ctx context.Context, tenantID string) error

	// GetTenantMetrics 获取租户的统计指标
	// 用于监控和分析
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	// 返回：
	//   - *TenantMetrics: 租户统计指标
	//   - error: 查询失败时返回错误
	GetTenantMetrics(ctx context.Context, tenantID string) (*TenantMetrics, error)

	// GetAllMetrics 获取所有租户的汇总统计指标
	// 用于系统级别的监控和分析
	// 参数：
	//   - ctx: 请求上下文
	// 返回：
	//   - *SystemMetrics: 系统统计指标
	//   - error: 查询失败时返回错误
	GetAllMetrics(ctx context.Context) (*SystemMetrics, error)

	// IncrementRequestCount 增加租户的请求计数
	// 用于租户级别的 QPS 统计和配额管理
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - count: 增量值（默认为 1）
	// 返回：
	//   - error: 更新失败时返回错误
	IncrementRequestCount(ctx context.Context, tenantID string, count int64) error

	// UpdateLastActivityAt 更新租户的最后活跃时间
	// 该方法在租户下任意设备认证成功时调用
	// 参数：
	//   - ctx: 请求上下文
	//   - tenantID: 租户标识符
	//   - lastActivityAt: 最后活跃时间
	// 返回：
	//   - error: 更新失败时返回错误
	UpdateLastActivityAt(ctx context.Context, tenantID string, lastActivityAt time.Time) error
}

// TenantMetrics 租户统计指标
type TenantMetrics struct {
	TenantID            string    // 租户 ID
	TotalDevices        int64     // 设备总数
	ActiveDevices       int64     // 活跃设备数（24 小时内）
	TotalTokensIssued   int64     // 累计颁发令牌数
	TokensIssuedToday   int64     // 今日颁发令牌数
	TotalRequestsToday  int64     // 今日总请求数
	SuccessRequestRate  float64   // 请求成功率（%）
	AverageLatencyMs    float64   // 平均延迟（毫秒）
	P95LatencyMs        float64   // P95 延迟（毫秒）
	RateLimitHitsToday  int64     // 今日限流触发次数
	TokenRevocations    int64     // 累计令牌吊销次数
	LastActivityAt      time.Time // 最后活跃时间
	StorageUsedBytes    int64     // 存储使用量（字节）
	BandwidthUsedBytes  int64     // 带宽使用量（字节）
	CurrentMonthlyBill  float64   // 当月账单（美元）
}

// SystemMetrics 系统统计指标（所有租户的汇总）
type SystemMetrics struct {
	TotalTenants        int64                        // 租户总数
	ActiveTenants       int64                        // 活跃租户数（7 天内）
	TotalDevices        int64                        // 设备总数
	ActiveDevices       int64                        // 活跃设备数（24 小时内）
	TotalTokensIssued   int64                        // 累计颁发令牌数
	TokensIssuedToday   int64                        // 今日颁发令牌数
	TotalRequestsToday  int64                        // 今日总请求数
	AverageQPS          float64                      // 平均 QPS
	PeakQPS             float64                      // 峰值 QPS
	SuccessRequestRate  float64                      // 请求成功率（%）
	AverageLatencyMs    float64                      // 平均延迟（毫秒）
	P95LatencyMs        float64                      // P95 延迟（毫秒）
	P99LatencyMs        float64                      // P99 延迟（毫秒）
	RateLimitHitsToday  int64                        // 今日限流触发次数
	ByStatus            map[models.TenantStatus]int64 // 按状态统计租户数
	StorageUsedGB       float64                      // 存储使用量（GB）
	BandwidthUsedGB     float64                      // 带宽使用量（GB）
	TotalMonthlyRevenue float64                      // 当月总收入（美元）
}

// TenantQuery 租户查询参数
// 用于复杂查询场景（如管理端的租户列表筛选）
type TenantQuery struct {
	TenantID         string              // 租户 ID（可选，模糊匹配）
	Name             string              // 租户名称（可选，模糊匹配）
	Status           models.TenantStatus // 租户状态（可选）
	CreatedAfter     *time.Time          // 创建时间下界（可选）
	CreatedBefore    *time.Time          // 创建时间上界（可选）
	LastActivityAfter  *time.Time        // 最后活跃时间下界（可选）
	LastActivityBefore *time.Time        // 最后活跃时间上界（可选）
	MinDevices       int64               // 最小设备数（可选）
	MaxDevices       int64               // 最大设备数（可选）
	Limit            int                 // 每页数量（默认 100，最大 1000）
	Offset           int                 // 偏移量
	OrderBy          string              // 排序字段（如 "created_at DESC"）
}

// FindByQuery 根据查询条件查询租户（高级查询接口）
// 该方法用于管理端的复杂查询场景
// 参数：
//   - ctx: 请求上下文
//   - query: 查询参数
//
// 返回：
//   - []*models.Tenant: 租户切片
//   - int64: 总记录数
//   - error: 查询失败时返回错误
//
// FindByQuery(ctx context.Context, query TenantQuery) ([]*models.Tenant, int64, error)

//Personal.AI order the ending
