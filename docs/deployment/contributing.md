# CBC Auth Service - 贡献指南

欢迎贡献 CBC 认证服务项目！本文档将指导您如何参与项目开发。

## 目录

- [开发环境搭建](#开发环境搭建)
- [代码规范](#代码规范)
- [提交规范](#提交规范)
- [分支策略](#分支策略)
- [测试要求](#测试要求)
- [Pull Request 流程](#pull-request-流程)
- [Issue 模板](#issue-模板)

---

## 开发环境搭建

### 1. 前置要求

- **Go 版本**：1.21+
- **Docker**：用于运行本地依赖服务（PostgreSQL、Redis、Vault）
- **Git**：版本控制
- **Make**：构建工具

### 2. 克隆代码仓库

```bash
git clone https://github.com/turtacn/cbc.git
cd cbc
````

### 3. 安装依赖

```bash
# 下载 Go 模块依赖
go mod download

# 安装开发工具
make install-tools
```

### 4. 启动本地开发环境

```bash
# 使用 Docker Compose 启动依赖服务
docker-compose -f deployments/docker/docker-compose.dev.yaml up -d

# 等待服务启动
sleep 10

# 初始化数据库
make db-migrate-up

# 初始化 Vault（首次运行）
make vault-init
```

### 5. 运行服务

```bash
# 启动认证服务
make run

# 或使用 Air 进行热重载开发
air
```

### 6. 验证环境

```bash
# 健康检查
curl http://localhost:8080/health/live

# 查看指标
curl http://localhost:9090/metrics
```

---

## 代码规范

### 1. Go 代码风格

#### 遵循官方 Go 代码规范

* [Effective Go](https://go.dev/doc/effective_go)
* [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

#### 使用 golangci-lint 进行代码检查

```bash
# 运行所有 linter
make lint

# 自动修复可修复的问题
make lint-fix
````

#### 代码格式化

```bash
# 使用 gofmt 格式化代码
make fmt

# 使用 goimports 整理 import
go install golang.org/x/tools/cmd/goimports@latest
goimports -w .
```

### 2. 命名约定

#### 包命名

* 使用小写字母，不使用下划线或驼峰
* 简短且有意义
* 避免通用名称（如 `util`, `common`, `base`）

```go
// 好的示例
package token
package ratelimit
package middleware

// 不好的示例
package tokenUtils
package rate_limit
package common
```

#### 变量和函数命名

* 使用驼峰命名法（camelCase 或 PascalCase）
* 导出的标识符使用 PascalCase
* 私有标识符使用 camelCase
* 缩写词保持一致的大小写

```go
// 好的示例
var httpClient *http.Client
var userID string
func GenerateAccessToken() string

// 不好的示例
var HTTPClient *http.Client  // 应该是 httpClient 或 HTTPClient（如果导出）
var userId string            // 应该是 userID
func generateAccesstoken()   // 应该是 generateAccessToken
```

#### 接口命名

* 单方法接口以 "er" 结尾
* 多方法接口使用描述性名称

```go
// 好的示例
type Reader interface {
    Read(p []byte) (n int, err error)
}

type TokenService interface {
    IssueToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error)
    ValidateToken(ctx context.Context, token string) (*Claims, error)
    RevokeToken(ctx context.Context, token string) error
}

// 不好的示例
type ITokenService interface { ... }  // 不要使用 I 前缀
type TokenServiceInterface interface { ... }  // 不要使用 Interface 后缀
```

### 3. 错误处理

#### 使用自定义错误类型

```go
// 定义错误类型
type ValidationError struct {
    Field   string
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation error on field %s: %s", e.Field, e.Message)
}

// 使用错误
func ValidateRequest(req *Request) error {
    if req.TenantID == "" {
        return &ValidationError{
            Field:   "tenant_id",
            Message: "tenant_id is required",
        }
    }
    return nil
}
```

#### 错误包装

```go
import "fmt"

func ProcessToken(token string) error {
    claims, err := parseToken(token)
    if err != nil {
        return fmt.Errorf("failed to parse token: %w", err)
    }
    
    if err := validateClaims(claims); err != nil {
        return fmt.Errorf("invalid claims: %w", err)
    }
    
    return nil
}
```

#### 不要忽略错误

```go
// 不好的示例
db.Close()  // 忽略错误

// 好的示例
if err := db.Close(); err != nil {
    log.Printf("failed to close database: %v", err)
}
```

### 4. 注释规范

#### 包注释

```go
// Package token 提供 JWT 令牌的生成、验证和管理功能。
//
// 主要功能包括：
//   - 访问令牌和刷新令牌的生成
//   - 令牌签名和验证
//   - 令牌黑名单管理
//
// 使用示例：
//
//   svc := token.NewService(config)
//   tokenResp, err := svc.IssueToken(ctx, &TokenRequest{...})
package token
```

#### 函数注释

```go
// IssueToken 为指定租户和代理生成访问令牌和刷新令牌。
//
// 参数：
//   - ctx: 请求上下文，用于超时控制和追踪
//   - req: 令牌请求，包含租户 ID、代理 ID 等信息
//
// 返回值：
//   - *TokenResponse: 包含访问令牌、刷新令牌和过期时间
//   - error: 生成失败时返回错误
//
// 可能的错误：
//   - ErrInvalidTenant: 租户不存在或已禁用
//   - ErrInvalidAgent: 代理不存在或未授权
//   - ErrRateLimitExceeded: 超过速率限制
func (s *Service) IssueToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
    // 实现...
}
```

#### 类型注释

```go
// TokenRequest 表示令牌颁发请求。
type TokenRequest struct {
    // TenantID 是租户的唯一标识符（必填）
    TenantID string `json:"tenant_id" validate:"required"`
    
    // AgentID 是代理的唯一标识符（必填）
    AgentID string `json:"agent_id" validate:"required"`
    
    // Scopes 是请求的权限范围（可选）
    Scopes []string `json:"scopes,omitempty"`
}
```

### 5. 测试规范

#### 测试文件命名

- 测试文件以 `_test.go` 结尾
- 测试函数以 `Test` 开头
- 基准测试以 `Benchmark` 开头
- 示例函数以 `Example` 开头

```go
// token_test.go
package token

func TestIssueToken(t *testing.T) { ... }
func TestValidateToken(t *testing.T) { ... }
func BenchmarkIssueToken(b *testing.B) { ... }
func ExampleService_IssueToken() { ... }
````

#### 表驱动测试

```go
func TestValidateRequest(t *testing.T) {
    tests := []struct {
        name    string
        req     *TokenRequest
        wantErr bool
        errType error
    }{
        {
            name: "valid request",
            req: &TokenRequest{
                TenantID: "tenant-1",
                AgentID:  "agent-1",
            },
            wantErr: false,
        },
        {
            name: "missing tenant_id",
            req: &TokenRequest{
                AgentID: "agent-1",
            },
            wantErr: true,
            errType: &ValidationError{},
        },
        {
            name: "missing agent_id",
            req: &TokenRequest{
                TenantID: "tenant-1",
            },
            wantErr: true,
            errType: &ValidationError{},
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateRequest(tt.req)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateRequest() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if tt.wantErr && tt.errType != nil {
                if !errors.As(err, &tt.errType) {
                    t.Errorf("ValidateRequest() error type = %T, want %T", err, tt.errType)
                }
            }
        })
    }
}
```

#### 使用 testify 库

```go
import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestTokenService(t *testing.T) {
    // 使用 require 在致命错误时立即停止
    svc, err := NewService(config)
    require.NoError(t, err)
    require.NotNil(t, svc)
    
    // 使用 assert 进行非致命断言
    resp, err := svc.IssueToken(ctx, req)
    assert.NoError(t, err)
    assert.NotEmpty(t, resp.AccessToken)
    assert.NotEmpty(t, resp.RefreshToken)
}
```

#### Mock 和接口

```go
// 定义接口
type TokenStore interface {
    Save(ctx context.Context, token *Token) error
    Get(ctx context.Context, tokenID string) (*Token, error)
    Delete(ctx context.Context, tokenID string) error
}

// 使用 mockery 生成 mock
//go:generate mockery --name=TokenStore --output=mocks --outpkg=mocks

// 在测试中使用 mock
func TestServiceWithMock(t *testing.T) {
    mockStore := new(mocks.TokenStore)
    mockStore.On("Save", mock.Anything, mock.Anything).Return(nil)
    
    svc := &Service{store: mockStore}
    
    // 测试代码...
    
    mockStore.AssertExpectations(t)
}
```

#### 测试覆盖率

```bash
# 运行测试并生成覆盖率报告
go test -coverprofile=coverage.out ./...

# 查看覆盖率
go tool cover -func=coverage.out

# 生成 HTML 报告
go tool cover -html=coverage.out -o coverage.html
```

### 6. 日志规范

#### 使用结构化日志

```go
import "go.uber.org/zap"

// 初始化 logger
logger, _ := zap.NewProduction()
defer logger.Sync()

// 使用结构化字段
logger.Info("token issued",
    zap.String("tenant_id", tenantID),
    zap.String("agent_id", agentID),
    zap.Duration("ttl", ttl),
)

logger.Error("failed to validate token",
    zap.Error(err),
    zap.String("token_id", tokenID),
)
```

#### 日志级别

* **Debug**: 详细的调试信息
* **Info**: 一般信息性消息
* **Warn**: 警告消息，表示潜在问题
* **Error**: 错误消息，表示失败但可恢复
* **Fatal**: 严重错误，导致程序退出

```go
logger.Debug("validating token claims", zap.Any("claims", claims))
logger.Info("rate limit check passed", zap.String("tenant_id", tenantID))
logger.Warn("token near expiration", zap.Duration("remaining", remaining))
logger.Error("database connection failed", zap.Error(err))
logger.Fatal("failed to initialize service", zap.Error(err))  // 谨慎使用
```

### 7. 性能优化

#### 避免不必要的内存分配

```go
// 不好的示例 - 每次调用都分配新内存
func BuildKey(parts ...string) string {
    result := ""
    for _, part := range parts {
        result += part + ":"
    }
    return result
}

// 好的示例 - 使用 strings.Builder
func BuildKey(parts ...string) string {
    var b strings.Builder
    for i, part := range parts {
        if i > 0 {
            b.WriteString(":")
        }
        b.WriteString(part)
    }
    return b.String()
}
```

#### 使用对象池

```go
var bufferPool = sync.Pool{
    New: func() interface{} {
        return new(bytes.Buffer)
    },
}

func ProcessData(data []byte) ([]byte, error) {
    buf := bufferPool.Get().(*bytes.Buffer)
    defer func() {
        buf.Reset()
        bufferPool.Put(buf)
    }()
    
    // 使用 buffer...
    return buf.Bytes(), nil
}
```

#### 并发处理

```go
func ProcessMultipleTenants(tenantIDs []string) error {
    var wg sync.WaitGroup
    errCh := make(chan error, len(tenantIDs))
    
    for _, tenantID := range tenantIDs {
        wg.Add(1)
        go func(id string) {
            defer wg.Done()
            if err := processTenant(id); err != nil {
                errCh <- err
            }
        }(tenantID)
    }
    
    wg.Wait()
    close(errCh)
    
    for err := range errCh {
        if err != nil {
            return err
        }
    }
    return nil
}
```

### 8. 安全最佳实践

#### 避免 SQL 注入

```go
// 不好的示例
query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID)
rows, err := db.Query(query)

// 好的示例
query := "SELECT * FROM users WHERE id = ?"
rows, err := db.Query(query, userID)
```

#### 敏感信息处理

```go
type Config struct {
    APIKey    string `json:"-"`  // 不序列化
    SecretKey string `json:"-"`
}

// 实现 Stringer 接口时隐藏敏感信息
func (c *Config) String() string {
    return fmt.Sprintf("Config{APIKey: *****, SecretKey: *****}")
}

// 日志中隐藏敏感信息
logger.Info("processing request",
    zap.String("user_id", userID),
    // 不要记录密码、令牌等敏感信息
)
```

#### 输入验证

```go
import "github.com/go-playground/validator/v10"

type Request struct {
    TenantID string `validate:"required,uuid"`
    Email    string `validate:"required,email"`
    Age      int    `validate:"gte=0,lte=130"`
}

func ValidateRequest(req *Request) error {
    validate := validator.New()
    return validate.Struct(req)
}
```

---

## 9. 文档编写

### API 文档

所有公共 API 都应该有清晰的文档，包括：

```go
// IssueToken 为指定租户和代理生成访问令牌和刷新令牌。
//
// 此方法执行以下步骤：
//  1. 验证请求参数
//  2. 检查速率限制
//  3. 生成令牌
//  4. 存储令牌元数据
//
// 请求示例：
//  req := &TokenRequest{
//      TenantID: "tenant-123",
//      AgentID:  "agent-456",
//      Scopes:   []string{"read", "write"},
//  }
//  resp, err := svc.IssueToken(ctx, req)
//
// 参数：
//  - ctx: 请求上下文，支持超时和取消
//  - req: 令牌请求对象，必须包含有效的租户 ID 和代理 ID
//
// 返回值：
//  - *TokenResponse: 成功时返回令牌响应，包含访问令牌和刷新令牌
//  - error: 失败时返回错误
//
// 错误类型：
//  - ErrInvalidRequest: 请求参数无效
//  - ErrUnauthorized: 代理未授权
//  - ErrRateLimitExceeded: 超过速率限制
//  - ErrInternal: 内部服务器错误
//
// 并发安全：此方法是并发安全的。
func (s *Service) IssueToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
    // 实现...
}
```

### README 文档

每个主要包都应该有一个 README.md 文件：

```markdown
# Token Service

令牌服务负责 JWT 令牌的生成、验证和管理。

## 功能特性

- ✅ 访问令牌和刷新令牌生成
- ✅ 令牌签名和验证
- ✅ 令牌黑名单管理
- ✅ 速率限制
- ✅ 多租户支持

## 快速开始

### 安装

```bash
go get github.com/your-org/cbc-auth/internal/token
```

### 基本使用

```go
import "github.com/your-org/cbc-auth/internal/token"

// 创建服务
config := &token.Config{
    AccessTokenTTL:  15 * time.Minute,
    RefreshTokenTTL: 7 * 24 * time.Hour,
    SigningKey:      "your-secret-key",
}

svc, err := token.NewService(config)
if err != nil {
    log.Fatal(err)
}

// 颁发令牌
resp, err := svc.IssueToken(ctx, &token.Request{
    TenantID: "tenant-1",
    AgentID:  "agent-1",
})
```

## 配置

| 参数 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| AccessTokenTTL | time.Duration | 15m | 访问令牌有效期 |
| RefreshTokenTTL | time.Duration | 168h | 刷新令牌有效期 |
| SigningKey | string | - | JWT 签名密钥 |

## 架构

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Token Svc   │
└──────┬──────┘
       │
       ├──────▶ Redis (黑名单)
       │
       └──────▶ Database (元数据)
```

## 测试

```bash
go test -v ./...
go test -cover ./...
```

## 贡献

请参阅 [CONTRIBUTING.md](../../docs/development/contributing.md)

## 许可证

[您的许可证]

---

## 10. Git 提交规范

### 提交消息格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

### 类型（type）

* **feat**: 新功能
* **fix**: 错误修复
* **docs**: 文档更新
* **style**: 代码格式调整（不影响功能）
* **refactor**: 重构（既不是新功能也不是错误修复）
* **perf**: 性能优化
* **test**: 测试相关
* **chore**: 构建过程或辅助工具的变动

### 示例

```bash
# 新功能
git commit -m "feat(token): add refresh token rotation

Implement automatic refresh token rotation for enhanced security.
When a refresh token is used, a new refresh token is issued and
the old one is revoked.

Closes #123"

# 错误修复
git commit -m "fix(ratelimit): correct sliding window calculation

Fix off-by-one error in sliding window rate limiter that caused
incorrect rate limit enforcement.

Fixes #456"

# 文档更新
git commit -m "docs(api): update token API documentation

Add examples and error code descriptions for token endpoints."

# 重构
git commit -m "refactor(middleware): simplify auth middleware

Extract common logic into helper functions and improve readability."
```

---

## 11. 代码审查清单

在提交 PR 前，请确保：

### 功能性

* [ ] 代码实现了需求中的所有功能
* [ ] 边界情况已被考虑和处理
* [ ] 错误处理完整且适当

### 代码质量

* [ ] 代码遵循项目编码规范
* [ ] 变量和函数命名清晰有意义
* [ ] 没有重复代码
* [ ] 复杂逻辑有适当注释

### 测试

* [ ] 添加了单元测试
* [ ] 测试覆盖率达标（>80%）
* [ ] 所有测试通过
* [ ] 测试用例覆盖正常和异常情况

### 性能

* [ ] 没有明显的性能问题
* [ ] 数据库查询已优化
* [ ] 避免了 N+1 查询问题
* [ ] 适当使用了缓存

### 安全性

* [ ] 敏感信息不在代码中硬编码
* [ ] 输入已验证和清理
* [ ] 没有 SQL 注入风险
* [ ] 权限检查已实施

### 文档

* [ ] API 文档已更新
* [ ] README 已更新（如需要）
* [ ] 代码注释清晰完整
* [ ] CHANGELOG 已更新

---

## 12. 常见问题

### Q: 如何处理数据库迁移？

A: 使用 `migrate` 命令：

```bash
# 创建新迁移
make migrate-create name=add_users_table

# 应用迁移
make migrate-up

# 回滚迁移
make migrate-down
```

### Q: 如何添加新的 API 端点？

A: 按以下步骤：

1. 在 `internal/handler` 中添加处理函数
2. 在 `internal/server` 中注册路由
3. 添加请求/响应结构体
4. 添加单元测试
5. 更新 API 文档

### Q: 如何调试 Redis 连接问题？

A: 检查以下方面：

```bash
# 检查 Redis 是否运行
redis-cli ping

# 查看 Redis 日志
docker logs redis

# 测试连接
redis-cli -h localhost -p 6379
```

### Q: 如何优化数据库查询？

A:

1. 使用 EXPLAIN ANALYZE 分析查询
2. 添加适当的索引
3. 避免 SELECT *
4. 使用批量操作
5. 考虑使用缓存

---

## 联系方式

如有任何问题，请通过以下方式联系我们：

* 📧 Email: [dev@yourcompany.com](mailto:dev@yourcompany.com)
* 💬 Slack: #cbc-auth-dev
* 🐛 Issues: [https://github.com/your-org/cbc-auth/issues](https://github.com/your-org/cbc-auth/issues)

---

**感谢您的贡献！** 🎉

