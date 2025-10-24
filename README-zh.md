<div align="center">
  <img src="logo.png" alt="cbc Logo" width="200" height="200">
  
  # CBC - 云脑认证
  
  [![构建状态](https://img.shields.io/github/workflow/status/turtacn/cbc/CI)](https://github.com/turtacn/cbc/actions)
  [![许可证](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
  [![Go 报告卡](https://goreportcard.com/badge/github.com/turtacn/cbc)](https://goreportcard.com/report/github.com/turtacn/cbc)
  [![发布版本](https://img.shields.io/github/v/release/turtacn/cbc)](https://github.com/turtacn/cbc/releases)
  [![代码覆盖率](https://codecov.io/gh/turtacn/cbc/branch/main/graph/badge.svg)](https://codecov.io/gh/turtacn/cbc)

  **面向数十亿设备的分布式身份认证与授权平台**
  
  简体中文 | [English](README.md)
</div>

---

## 🚀 核心使命

**CBC（CloudBrain-Cert，云脑认证）** 是一个前沿的、高性能的分布式身份认证与授权平台，旨在成为公网环境下数十亿终端设备的**信任锚点**。基于 OAuth 2.0 + JWT 标准和零信任架构原则构建，CBC 提供：

- **百万级并发令牌请求**处理能力
- **亚10毫秒令牌签发延迟**与水平扩展能力
- **多租户隔离**与独立密钥管理
- **实时令牌吊销**与分布式黑名单同步
- **全方位可观测性**（指标、日志、分布式追踪）

---

## 💡 为什么选择 CBC？

### 解决的核心痛点

| 痛点 | 传统方案 | CBC 方案 |
|------|---------|---------|
| **扩展性瓶颈** | 有状态会话管理难以应对百万级并发设备 | 无状态 JWT + Redis 集群 + 水平 Pod 自动伸缩，支持数十亿设备 |
| **安全与性能权衡** | 长效令牌（安全风险）或频繁认证（性能损失） | 双令牌模型：长效 Refresh Token（365天）+ 短效 Access Token（15分钟）+ 本地验签 |
| **复杂的多租户管理** | 租户间共享密钥存在交叉污染风险 | 通过 HashiCorp Vault 实现每租户密钥隔离与自动轮换 |
| **吊销延迟** | 传统黑名单存在同步滞后 | 基于 Redis 的分布式黑名单 + JTI 索引实现实时吊销 |
| **供应商锁定** | 专有方案，内部机制不透明 | 开源、标准 OAuth 2.0/JWT、云无关设计 |

### 核心价值主张

1. **极致并发**：处理 **100万+ 令牌请求/秒**，线性扩展
2. **全球规模**：支持 **1亿+ 设备代理**，地理分布式部署
3. **零信任原生**：基于上下文的访问控制与设备指纹
4. **开发者友好**：简洁的 REST API、全面的 SDK、详细的文档
5. **生产就绪**：经过实战检验的组件（PostgreSQL、Redis、Vault、Kafka）

---

## ✨ 核心特性

### 核心认证与授权

- ✅ **符合 OAuth 2.0 标准**：标准 `refresh_token` 授权流程
- ✅ **基于 JWT 的访问控制**：自包含、本地可验证的令牌
- ✅ **非对称加密**：RSA-4096 签名，每租户独立密钥对
- ✅ **设备注册代理**：通过 MGR 安全提供初始凭证
- ✅ **细粒度权限**：基于 Scope 的授权，PEP/PDP 分离

### 高级安全特性

- 🔒 **一次性 Refresh Token**：每次使用后自动轮换
- 🔒 **mTLS 双向认证**：MGR 与 CBC 通信加密
- 🔒 **设备指纹识别**：硬件绑定的信任根（支持 TPM/TEE）
- 🔒 **上下文感知访问**：基于位置、时间、设备健康度的策略执行
- 🔒 **完整审计追踪**：不可篡改的日志，JTI-TraceID 关联

### 高性能

- ⚡ **亚10毫秒令牌签发**：多级缓存（L1 进程内 + L2 Redis）
- ⚡ **水平扩展**：Kubernetes 原生，支持 HPA/VPA
- ⚡ **全球边缘部署**：GeoDNS + 区域集群实现低延迟
- ⚡ **优化的数据访问**：连接池、只读副本、查询优化

### 企业级可靠性

- 🛡️ **99.99% 正常运行时间 SLA**：多区域主主部署
- 🛡️ **优雅降级**：熔断器、重试机制、降级策略
- 🛡️ **灾难恢复**：跨区域密钥/黑名单同步
- 🛡️ **速率限制**：全局/租户/设备级 QPS 保护

### 可观测性

- 📊 **Prometheus 指标**：令牌签发率、延迟百分位、错误率
- 📊 **分布式追踪**：Jaeger 集成，端到端请求跟踪
- 📊 **集中式日志**：Loki 聚合，结构化 JSON 日志
- 📊 **Grafana 仪表盘**：预构建的关键 SLI/SLO 可视化

---

## 🏗️ 架构概览

CBC 采用**分层微服务架构**，职责清晰分离：

```mermaid
graph TB
    subgraph External[外部层（External Layer）]
        Agent[设备代理（Device Agent）]
        MGR[内网管理器（Intranet MGR）]
        IS[情报服务（Intelligence Service）]
    end
    
    subgraph CBC[CBC 集群（CBC Cluster）]
        LB[负载均衡器（Load Balancer）]
        API1[API Pod 1]
        API2[API Pod N]
        
        subgraph Services[业务逻辑层（Business Logic Layer）]
            AuthSvc[认证服务（Auth Service）]
            TokenSvc[令牌服务（Token Service）]
            PolicySvc[策略服务（Policy Service）]
            RevokeSvc[吊销服务（Revocation Service）]
        end
    end
    
    subgraph Data[数据层（Data Layer）]
        Redis[(Redis 集群<br/>（Redis Cluster）)]
        PG[(PostgreSQL 高可用<br/>（PostgreSQL HA）)]
        Vault[(Vault 密钥管理<br/>（Vault KMS）)]
        Kafka[(Kafka 消息队列<br/>（Kafka MQ）)]
    end
    
    Agent -->|HTTPS| LB
    MGR -->|mTLS| LB
    IS -->|获取公钥（Fetch Public Key）| LB
    
    LB --> API1
    LB --> API2
    API1 --> Services
    API2 --> Services
    
    Services --> Redis
    Services --> PG
    Services --> Vault
    Services --> Kafka
    
    style CBC fill:#e6ffe6
    style Data fill:#ccffcc
````

👉 **详细架构设计**：[docs/architecture.md](docs/architecture.md)
👉 **完整 API 规范**：[docs/apis.md](docs/apis.md)

---

## 🚀 快速开始

### 前置要求

* Go 1.21+（从源码构建）
* Docker & Docker Compose（本地开发）
* Kubernetes 1.25+（生产部署）

### 安装

#### 方式 1：通过 Go 安装 CLI

```bash
go install github.com/turtacn/cbc/cmd/cbc-cli@latest
```

#### 方式 2：下载预构建二进制文件

```bash
# Linux/macOS
curl -sSL https://github.com/turtacn/cbc/releases/latest/download/cbc-linux-amd64 -o cbc-cli
chmod +x cbc-cli
sudo mv cbc-cli /usr/local/bin/

# 验证安装
cbc-cli version
```

#### 方式 3：使用 Docker 运行

```bash
docker pull turtacn/cbc:latest
docker run -d -p 8080:8080 --name cbc-server turtacn/cbc:latest
```

### 快速演示

```bash
# 1. 启动本地开发环境（PostgreSQL、Redis、Vault）
docker-compose up -d

# 2. 初始化数据库模式
cbc-cli db migrate --config configs/dev.yaml

# 3. 启动 CBC 服务器
cbc-server --config configs/dev.yaml

# 4. 注册新租户
cbc-cli tenant create 
  --name "我的公司" 
  --admin-email "admin@example.com"

# 输出：
# ✅ 租户创建成功！
# 租户 ID: tenant-abc123
# Vault 密钥路径: /cbc/tenants/tenant-abc123/signing-key

# 5. 为设备入网注册 MGR 凭证
cbc-cli mgr create 
  --tenant-id "tenant-abc123" 
  --mgr-name "内网网关" 
  --output mgr-credentials.json

# 输出：
# ✅ MGR 创建成功！
# MGR Client ID: mgr-xyz789
# MGR Secret: ***(已保存到 mgr-credentials.json)

# 6. 模拟设备注册（通过 MGR 代理）
cbc-cli device register 
  --tenant-id "tenant-abc123" 
  --agent-id "device-001" 
  --mgr-client-id "mgr-xyz789" 
  --mgr-secret "$(jq -r .secret mgr-credentials.json)" 
  --output device-refresh-token.txt

# 输出：
# ✅ 设备注册成功！
# Refresh Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
# 有效期: 31536000 秒（365天）

# 7. 获取 Access Token（模拟漫游代理）
cbc-cli token get 
  --refresh-token "$(cat device-refresh-token.txt)" 
  --scope "intelligence:read intelligence:write"

# 输出：
# ✅ Access Token 签发成功！
# Access Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
# 有效期: 900 秒（15分钟）
# Scope: intelligence:read intelligence:write

# 8. 本地验证 Access Token（模拟情报服务）
cbc-cli token verify 
  --token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." 
  --tenant-id "tenant-abc123"

# 输出：
# ✅ 令牌有效！
# Subject: device-001
# Tenant: tenant-abc123
# Scope: intelligence:read intelligence:write
# 过期时间: 2025-10-23T15:30:00Z
```

### 高级用法 - 令牌吊销

```bash
# 通过 JTI 吊销特定 Refresh Token
cbc-cli token revoke 
  --jti "refresh-jti-12345" 
  --reason "设备报失"

# 输出：
# ✅ 令牌吊销成功！
# 吊销的 JTI: refresh-jti-12345
# Redis 集群黑名单已更新

# 吊销特定设备的所有令牌
cbc-cli device revoke 
  --tenant-id "tenant-abc123" 
  --agent-id "device-001" 
  --reason "安全事件"

# 输出：
# ✅ device-001 的所有令牌已吊销！
# 影响的令牌: 3 个（1 个 Refresh Token + 2 个仍有效的 Access Token）
```

### 性能测试

```bash
# 运行内置负载测试
cbc-cli benchmark 
  --target http://localhost:8080 
  --concurrency 1000 
  --duration 60s 
  --scenario token-issuance

# 输出：
# 📊 基准测试结果：
# 总请求数: 1,234,567
# 成功率: 99.98%
# 平均延迟: 8.3ms
# P95 延迟: 15.2ms
# P99 延迟: 28.7ms
# 吞吐量: 20,576 req/s
```

---

## 📚 文档

* **[架构设计](docs/architecture.md)**：详细的系统设计和技术决策
* **[API 参考](docs/apis.md)**：完整的 OpenAPI 3.0 规范
* **[部署指南](docs/deployment.md)**：Kubernetes、Docker、云服务商指南
* **[安全最佳实践](docs/security.md)**：加固检查清单和合规性
* **[开发者指南](docs/development.md)**：贡献工作流和代码标准

---

## 🤝 贡献

我们欢迎社区贡献！无论是：

* 🐛 Bug 报告和修复
* ✨ 新特性和增强
* 📖 文档改进
* 🌍 翻译

**在提交 PR 之前，请阅读我们的 [贡献指南](CONTRIBUTING.md)。**

### 开发工作流

```bash
# 1. Fork 并克隆仓库
git clone https://github.com/YOUR_USERNAME/cbc.git
cd cbc

# 2. 创建特性分支
git checkout -b feature/amazing-feature

# 3. 进行更改并添加测试
go test ./...

# 4. 运行 linters 和 formatters
make lint
make fmt

# 5. 使用约定式提交
git commit -m "feat(auth): 添加设备指纹支持"

# 6. 推送并创建 Pull Request
git push origin feature/amazing-feature
```

---

## 📄 许可证

CBC 采用 **Apache License 2.0** 许可。
详见 [LICENSE](LICENSE) 文件。

```
Copyright 2025 CBC 作者

根据 Apache 许可证 2.0 版（"许可证"）授权；
除非遵守许可证，否则您不得使用此文件。
您可以在以下网址获得许可证副本：

    http://www.apache.org/licenses/LICENSE-2.0

除非适用法律要求或书面同意，否则根据许可证分发的软件
按"原样"分发，不附带任何明示或暗示的保证或条件。
请参阅许可证以了解许可证下特定语言的权限和限制。
```

---

## 🙏 致谢

CBC 站在巨人的肩膀上：

* [OAuth 2.0](https://oauth.net/2/) - 行业标准授权框架
* [JWT](https://jwt.io/) - 用于安全数据交换的 JSON Web Tokens
* [HashiCorp Vault](https://www.vaultproject.io/) - 密钥和加密管理
* [Kubernetes](https://kubernetes.io/) - 容器编排平台
* [Go](https://go.dev/) - 高效、可靠、简单的编程语言

---

## 📞 社区与支持

* **GitHub Issues**：[报告 Bug 或请求功能](https://github.com/turtacn/cbc/issues)
* **Discussions**：[提问和分享想法](https://github.com/turtacn/cbc/discussions)
* **Slack**：[加入我们的社区工作区](#)（即将推出）
* **邮箱**：[cbc-dev@turtacn.com](mailto:cbc-dev@turtacn.com)

---

<div align="center">
  由 CBC 社区用 ❤️ 制作

⭐ **如果 CBC 帮助保护您的基础设施，请在 GitHub 上给我们 Star！**

</div>