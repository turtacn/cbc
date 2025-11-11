<div align="center">
  <img src="logo.png" alt="cbc Logo" width="200" height="200">

  # CBC - CloudBrain Certification

  [![构建状态](https://img.shields.io/github/workflow/status/turtacn/cbc/CI)](https://github.com/turtacn/cbc/actions)
  [![许可证](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
  [![Go 报告卡](https://goreportcard.com/badge/github.com/turtacn/cbc)](https://goreportcard.com/report/github.com/turtacn/cbc)

  **一个企业级的身份认证与授权平台**

  简体中文 | [English](README.md)
</div>

---

## 🚀 使命宣言

**CBC (CloudBrain-Cert)** 是一个企业级、高性能的身份认证和授权平台，旨在作为现代网络环境中设备和服务的 **信任锚**。基于 OAuth 2.0 和 JWT 等开放标准，并遵循领域驱动设计（DDD）原则，CBC 为零信任架构提供了一个健壮且可扩展的基础。

本仓库包含核心后端服务，负责令牌的颁发、验证、撤销和密钥管理。

---

## 🏗️ 架构概览

该服务采用基于领域驱动设计（DDD）原则的分层架构构建，确保了清晰的关注点分离。

- **领域层 (Domain Layer)**: 包含核心业务逻辑、模型（例如 `Token`, `Key`, `Tenant`）以及仓库和服务的接口。
- **应用层 (Application Layer)**: 编排领域逻辑以执行特定于应用程序的任务（例如 `AuthAppService`, `DeviceAuthAppService`）。它使用数据传输对象（DTO）与接口层交互。
- **基础设施层 (Infrastructure Layer)**: 提供领域接口的具体实现，与数据库、缓存和密钥库等外部系统交互。这包括 PostgreSQL 和 Redis 的仓库，以及 HashiCorp Vault 的客户端。
- **接口层 (Interface Layer)**: 通过 RESTful API（使用 Gin）和 gRPC 服务向外界暴露应用程序的功能。

```mermaid
graph TB
    subgraph "接口层 (传输)"
        Gin[Gin HTTP 服务器]
        GRPC[gRPC 服务器]
    end

    subgraph "应用层 (用例)"
        AuthSvc[AuthAppService]
        DeviceAuthSvc[DeviceAuthAppService]
        TenantSvc[TenantAppService]
    end

    subgraph "领域层 (核心逻辑)"
        direction LR
        Models[模型, 例如 Token, Key]
        RepoInterfaces[仓库接口]
        SvcInterfaces[服务接口]
    end

    subgraph "基础设施层 (外部系统)"
        Postgres[PostgreSQL (GORM/PGX)]
        Redis[Redis]
        Vault[HashiCorp Vault]
        Kafka[Apache Kafka]
    end

    Gin --> AuthSvc
    GRPC --> AuthSvc
    AuthSvc --> SvcInterfaces
    AuthSvc --> RepoInterfaces

    RepoInterfaces -- 由...实现 --> Postgres
    RepoInterfaces -- 由...实现 --> Redis
    SvcInterfaces -- 由...实现 --> Vault
    SvcInterfaces -- 由...实现 --> Kafka

    style Gin fill:#add8e6
    style GRPC fill:#add8e6
    style Postgres fill:#d3d3d3
    style Redis fill:#d3d3d3
    style Vault fill:#d3d3d3
    style Kafka fill:#d3d3d3
```

---

## ✨ 已实现的主要功能

- **OAuth 2.0 设备授权流程**: 实现了 RFC 8628，适用于输入受限的设备。
- **基于 JWT 的身份验证**: 颁发和验证 RS256 签名的 JSON Web 令牌。
- **多租户**: 支持隔离的租户，每个租户都有自己独立的加密密钥集。
- **密钥管理**:
    - 与 HashiCorp Vault 集成作为密钥提供程序。
    - 提供 RESTful 端点 (`/api/v1/jwks/:tenant_id`) 以 JSON Web Key Set (JWKS) 格式暴露公钥。
- **持久化**:
    - **PostgreSQL**: 用于存储密钥、租户、设备和令牌等主要记录。
    - **Redis**: 用于缓存、设备流程中的会话管理以及令牌黑名单存储。
- **HTTP/gRPC API**:
    - **公共 API (Gin)**: 用于核心认证流程 (`/token`, `/revoke` 等)。
    - **内部 API (Gin)**: 一个独立的、非公开的 API，用于管理任务，例如接收由机器学习驱动的风险评分 (`/_internal/ml/risk`)。
    - **gRPC API**: 提供令牌颁发和撤销的服务。
- **中间件**:
    - **可观测性**: 为所有 HTTP 请求提供 Prometheus 指标和 OpenTelemetry 链路追踪。
    - **安全性**: 速率限制（基于 IP）、幂等性检查（基于 JTI）和 JWT 身份验证。
- **命令行工具 (`cbc-admin`)**: 一个用于与服务交互的管理 CLI，包括管理密钥和合规性的命令。

---

## 🚀 快速入门

### 先决条件

* Go (版本 1.21 或更高)
* Docker 和 Docker Compose
* `make`

### 1. 配置

服务使用 `config/config.yaml` 进行配置。项目提供了一个示例配置文件。您可能需要根据本地环境调整数据库、Redis 或 Vault 的连接详细信息。

### 2. 运行依赖项

项目包含一个 `docker-compose.yml` 文件，可以轻松运行所需的外部服务（PostgreSQL 和 Redis）。

```bash
docker-compose up -d
```

这将在 `5432` 端口上启动 PostgreSQL，在 `6379` 端口上启动 Redis。

### 3. 数据库迁移

在首次运行应用程序之前，您需要应用数据库模式。迁移文件位于 `migrations/` 目录中。

*（注意：目前尚未集成迁移工具。您需要使用 `psql` 等工具手动应用 SQL 脚本。）*

### 4. 构建并运行服务器

您可以从 `cmd/server` 目录构建并运行主应用程序服务器。

```bash
# 进入服务器目录
cd cmd/server

# 构建二进制文件
go build .

# 运行服务器
./server
```

默认情况下，主 HTTP 服务器将运行在 `8090` 端口，内部 HTTP 服务器在 `9091` 端口，gRPC 服务器在 `50051` 端口。

### 5. 使用管理 CLI

`cbc-admin` 工具用于执行管理任务。

```bash
# 进入 cbc-admin 目录
cd cmd/cbc-admin

# 构建二进制文件
go build .

# 查看可用命令
./cbc-admin --help
```

---

## 🛠️ 开发

### 运行测试

项目包括单元测试、集成测试和端到端（E2E）测试。

```bash
# 运行所有测试
make test

# 运行测试并生成覆盖率报告
make coverage
```

### 生成模拟对象 (Mocks)

项目使用 `mockery` 为接口生成模拟对象。如果您更改了某个接口，则必须重新生成模拟对象。

```bash
# 如果尚未安装，请安装 mockery
go install github.com/vektra/mockery/v2@latest

# 重新生成所有模拟对象
make mock
```

---

## 🤝 贡献

欢迎社区贡献！请阅读我们的 `CONTRIBUTING.md` 指南，以了解我们的开发流程、如何提出错误修复和改进建议，以及如何构建和测试您的更改。

---

## 📄 许可证

本项目采用 **Apache License 2.0** 许可证。详情请参阅 [LICENSE](LICENSE) 文件。
