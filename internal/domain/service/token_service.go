// Package service 定义领域服务接口
// Token 领域服务接口 - 负责 Token 相关的核心业务逻辑
package service

import (
	"context"
	"time"

	"github.com/turtacn/cbc/internal/domain/models"
)

// TokenService Token 领域服务接口
// 定义 Token 相关的核心业务方法，包括颁发、刷新、验证、吊销等操作
type TokenService interface {
	// IssueTokenPair 颁发 Refresh Token 和 Access Token 对
	// 用于设备注册或 MGR 代理注册场景
	// 参数:
	//   ctx: 上下文对象
	//   tenantID: 租户标识符
	//   agentID: 终端 Agent 唯一标识符
	//   deviceFingerprint: 设备指纹哈希值（可选）
	//   scope: 权限范围列表
	//   metadata: 额外元数据（如 IP 地址、User-Agent 等）
	// 返回:
	//   refreshToken: 长效 Refresh Token
	//   accessToken: 短效 Access Token
	//   error: 错误信息
	IssueTokenPair(
		ctx context.Context,
		tenantID string,
		agentID string,
		deviceFingerprint string,
		scope []string,
		metadata map[string]interface{},
	) (refreshToken *models.Token, accessToken *models.Token, err error)

	// RefreshToken 使用 Refresh Token 获取新的 Access Token
	// 实现一次性 Refresh Token 机制（旧 Refresh Token 立即失效）
	// 参数:
	//   ctx: 上下文对象
	//   refreshTokenString: Refresh Token 字符串
	//   requestedScope: 请求的权限范围（可选，默认继承原有 scope）
	// 返回:
	//   newRefreshToken: 新的 Refresh Token（一次性令牌）
	//   accessToken: 新的 Access Token
	//   error: 错误信息
	RefreshToken(
		ctx context.Context,
		refreshTokenString string,
		requestedScope []string,
	) (newRefreshToken *models.Token, accessToken *models.Token, err error)

	// VerifyToken 验证 Token 的有效性
	// 检查签名、有效期、吊销状态等
	// 参数:
	//   ctx: 上下文对象
	//   tokenString: Token 字符串
	//   tokenType: Token 类型（refresh_token 或 access_token）
	//   tenantID: 租户标识符（用于获取公钥）
	// 返回:
	//   token: 解析后的 Token 模型
	//   error: 错误信息
	VerifyToken(
		ctx context.Context,
		tokenString string,
		tokenType models.TokenType,
		tenantID string,
	) (*models.Token, error)

	// RevokeToken 吊销 Token
	// 将 Token 的 JTI 加入黑名单，使其立即失效
	// 参数:
	//   ctx: 上下文对象
	//   jti: Token 唯一标识符
	//   tenantID: 租户标识符
	//   reason: 吊销原因
	// 返回:
	//   error: 错误信息
	RevokeToken(
		ctx context.Context,
		jti string,
		tenantID string,
		reason string,
	) error

	// IsTokenRevoked 检查 Token 是否已被吊销
	// 查询黑名单（Redis + PostgreSQL 双重检查）
	// 参数:
	//   ctx: 上下文对象
	//   jti: Token 唯一标识符
	// 返回:
	//   revoked: 是否已吊销
	//   error: 错误信息
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)

	// GenerateAccessToken 生成 Access Token
	// 基于 Refresh Token 的信息生成短效 Access Token
	// 参数:
	//   ctx: 上下文对象
	//   refreshToken: Refresh Token 模型
	//   requestedScope: 请求的权限范围（可选）
	// 返回:
	//   accessToken: Access Token 模型
	//   error: 错误信息
	GenerateAccessToken(
		ctx context.Context,
		refreshToken *models.Token,
		requestedScope []string,
	) (*models.Token, error)

	// ValidateTokenClaims 验证 Token Claims 的业务规则
	// 检查 Token 是否符合业务约束（如设备指纹匹配、IP 白名单等）
	// 参数:
	//   ctx: 上下文对象
	//   token: Token 模型
	//   validationContext: 验证上下文（如当前 IP、设备指纹等）
	// 返回:
	//   valid: 是否有效
	//   error: 错误信息
	ValidateTokenClaims(
		ctx context.Context,
		token *models.Token,
		validationContext map[string]interface{},
	) (bool, error)

	// IntrospectToken Token 内省（可选）
	// 为不支持本地验签的业务服务提供 Token 验证接口
	// 参数:
	//   ctx: 上下文对象
	//   tokenString: Token 字符串
	//   tokenTypeHint: Token 类型提示（refresh_token 或 access_token）
	// 返回:
	//   introspection: Token 内省响应
	//   error: 错误信息
	IntrospectToken(
		ctx context.Context,
		tokenString string,
		tokenTypeHint string,
	) (*models.TokenIntrospection, error)

	// CleanupExpiredTokens 清理过期 Token 元数据
	// 定期清理数据库中已过期的 Token 记录
	// 参数:
	//   ctx: 上下文对象
	//   before: 清理此时间点之前过期的 Token
	// 返回:
	//   deletedCount: 删除的记录数
	//   error: 错误信息
	CleanupExpiredTokens(ctx context.Context, before time.Time) (int64, error)
}

// TokenServiceConfig Token 服务配置
type TokenServiceConfig struct {
	// RefreshTokenTTL Refresh Token 有效期（秒）
	RefreshTokenTTL int64

	// AccessTokenTTL Access Token 有效期（秒）
	AccessTokenTTL int64

	// EnableOneTimeRefreshToken 是否启用一次性 Refresh Token
	EnableOneTimeRefreshToken bool

	// AllowedClockSkew 允许的时钟偏差（秒）
	AllowedClockSkew int64

	// DefaultScope 默认权限范围
	DefaultScope []string
}

//Personal.AI order the ending
