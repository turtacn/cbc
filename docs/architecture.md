# cbc (CloudBrain-Cert) 项目架构设计文档

## 目录

1. [项目概述](#1-项目概述)
2. [领域问题全景](#2-领域问题全景)
3. [解决方案全景](#3-解决方案全景)
4. [系统架构设计](#4-系统架构设计)
5. [核心组件详细设计](#5-核心组件详细设计)
6. [关键业务场景详细设计](#6-关键业务场景详细设计)
7. [技术选型与实现策略](#7-技术选型与实现策略)
8. [项目目录结构](#8-项目目录结构)
9. [部署架构](#9-部署架构)
10. [预期效果与展望](#10-预期效果与展望)
11. [参考资料](#11-参考资料)

---

## 1. 项目概述

### 1.1 项目定位

**cbc（CloudBrain-Cert）** 是一个面向亿级终端设备的分布式身份认证与授权平台，致力于构建零信任架构下的可信终端身份体系。作为整个安全漫游访问体系的核心信任锚点，cbc 基于 OAuth 2.0 协议和 JWT 令牌机制，通过非对称加密和双令牌设计，为海量终端 Agent 提供高性能、高可用、高安全的认证授权服务。

### 1.2 核心价值

* **极简先进**：遵循标准协议（OAuth 2.0 + JWT），无状态设计，易于理解和集成
* **极致并发**：支持百万级 QPS，应对海量终端同时认证的挑战
* **全面安全**：端到端加密、密钥轮换、双令牌机制、细粒度权限控制
* **高可用**：多区域部署、水平扩展、故障自愈
* **逐步演进**：模块化设计，支持从基础认证向零信任架构的平滑演进

### 1.3 关键指标

| 指标类型       | 目标值        | 说明                       |
| :--------- | :--------- | :----------------------- |
| **并发处理能力** | ≥100万 QPS  | 令牌颁发与验证的峰值吞吐量            |
| **设备规模**   | ≥1亿 Agent  | 支持的最大终端设备数量              |
| **令牌颁发延迟** | ≤50ms（P99） | 从请求到返回 Access Token 的时延  |
| **系统可用性**  | ≥99.99%    | 年度服务不可用时间 ≤52.56分钟       |
| **令牌吊销时效** | ≤1秒        | Refresh Token 吊销后的全局生效时间 |
| **密钥轮换周期** | 30-90天     | 租户 JWT 签名密钥的自动轮换间隔       |

---

## 2. 领域问题全景

### 2.1 核心挑战矩阵

```mermaid
graph TB
    subgraph CP[核心挑战（Core Problems）]
        direction TB
        CP1[身份信任问题<br/>（Identity Trust）]
        CP2[性能与规模挑战<br/>（Performance & Scale）]
        CP3[安全风险防御<br/>（Security Risks）]
        CP4[运维复杂度<br/>（Operational Complexity）]
    end
    
    subgraph CP1D[身份信任问题详细]
        direction LR
        T1[漫游 Agent 身份可信度]
        T2[凭证生命周期管理]
        T3[多租户密钥安全隔离]
    end
    
    subgraph CP2D[性能与规模挑战详细]
        direction LR
        S1[百万并发令牌请求]
        S2[亿级设备 Agent 管理]
        S3[全球低延迟访问]
    end
    
    subgraph CP3D[安全风险防御详细]
        direction LR
        R1[凭证泄露与滥用]
        R2[中间人攻击]
        R3[重放攻击]
        R4[内部威胁]
    end
    
    CP1 --> CP1D
    CP2 --> CP2D
    CP3 --> CP3D
    
    style CP fill:#ffe6e6
    style CP1D fill:#fff4e6
    style CP2D fill:#e6f3ff
    style CP3D fill:#ffe6f0
```

### 2.2 身份信任问题

#### 2.2.1 漫游 Agent 身份可信度保障

**问题描述**：终端 Agent 在公网环境下漫游，需要持续证明其身份的合法性，且不受网络环境变化、中间人攻击等因素影响。

**挑战要点**：

* 如何在设备首次注册时建立初始信任根？
* 如何在漫游过程中持续验证设备身份？
* 如何防止设备指纹伪造或克隆？

#### 2.2.2 凭证生命周期管理

**问题描述**：Refresh Token 和 Access Token 的生命周期需要精细化管理，既要保证安全性（防止长期有效令牌被滥用），又要保证用户体验（避免频繁重新认证）。

**挑战要点**：

* Refresh Token 的有效期设计（长期 vs 短期）
* Access Token 的刷新策略（主动 vs 被动）
* 令牌吊销的实时性与全局一致性
* 一次性使用令牌（One-Time Token）的实现

#### 2.2.3 多租户密钥安全隔离

**问题描述**：系统需要支持数千甚至数万租户，每个租户的 JWT 签名密钥必须独立管理和隔离，防止交叉泄露。

**挑战要点**：

* 密钥的集中存储与安全访问
* 密钥的自动轮换与版本管理
* 密钥泄露后的快速响应机制

### 2.3 性能与规模挑战

#### 2.3.1 百万并发令牌请求

**问题描述**：在特定场景下（如设备集中上线、定时策略更新），可能在短时间内产生百万级 QPS 的令牌请求。

**技术难点**：

* 认证服务的瓶颈识别与优化
* 数据库与缓存的压力分散
* 热点数据的访问优化

#### 2.3.2 亿级设备 Agent 管理

**问题描述**：系统需要支持亿级规模的设备注册、凭证管理和访问控制。

**技术难点**：

* 海量数据的存储与查询优化
* 分布式缓存的数据分片与一致性
* 全局唯一标识符（Agent ID、JTI）的生成策略

#### 2.3.3 全球低延迟访问

**问题描述**：终端 Agent 分布在全球各地,需要就近访问认证服务以降低延迟。

**技术难点**：

* 多区域部署的架构设计
* 跨区域数据同步的时效性
* 全球负载均衡与流量调度

### 2.4 安全风险防御

#### 2.4.1 凭证泄露与滥用

**风险描述**：Refresh Token 或 Access Token 被窃取后，攻击者可以冒充合法 Agent 访问业务资源。

**防御要求**：

* Refresh Token 的加密存储与传输
* Access Token 的短生命周期设计
* 令牌黑名单的实时同步

#### 2.4.2 中间人攻击（MITM）

**风险描述**：攻击者在 Agent 与认证服务之间进行流量劫持，窃取凭证或篡改数据。

**防御要求**：

* 全链路 TLS 加密
* 双向 TLS 认证（mTLS）
* 证书固定（Certificate Pinning）

#### 2.4.3 重放攻击

**风险描述**：攻击者截获合法请求后重复发送，试图绕过认证。

**防御要求**：

* JWT 的唯一标识符（JTI）机制
* 时间戳验证与时间窗口限制
* 一次性令牌设计
# cbc (CloudBrain-Cert) 项目架构设计文档

## 目录

1. [项目概述](#1-项目概述)
2. [领域问题全景](#2-领域问题全景)
3. [解决方案全景](#3-解决方案全景)
4. [系统架构设计](#4-系统架构设计)
5. [核心组件详细设计](#5-核心组件详细设计)
6. [关键业务场景详细设计](#6-关键业务场景详细设计)
7. [技术选型与实现策略](#7-技术选型与实现策略)
8. [项目目录结构](#8-项目目录结构)
9. [部署架构](#9-部署架构)
10. [预期效果与展望](#10-预期效果与展望)
11. [参考资料](#11-参考资料)

---

## 1. 项目概述

### 1.1 项目定位

**cbc（CloudBrain-Cert）** 是一个面向亿级终端设备的分布式身份认证与授权平台，致力于构建零信任架构下的可信终端身份体系。作为整个安全漫游访问体系的核心信任锚点，cbc 基于 OAuth 2.0 协议和 JWT 令牌机制，通过非对称加密和双令牌设计，为海量终端 Agent 提供高性能、高可用、高安全的认证授权服务。

### 1.2 核心价值

* **极简先进**：遵循标准协议（OAuth 2.0 + JWT），无状态设计，易于理解和集成
* **极致并发**：支持百万级 QPS，应对海量终端同时认证的挑战
* **全面安全**：端到端加密、密钥轮换、双令牌机制、细粒度权限控制
* **高可用**：多区域部署、水平扩展、故障自愈
* **逐步演进**：模块化设计，支持从基础认证向零信任架构的平滑演进

### 1.3 关键指标

| 指标类型       | 目标值        | 说明                       |
| :--------- | :--------- | :----------------------- |
| **并发处理能力** | ≥100万 QPS  | 令牌颁发与验证的峰值吞吐量            |
| **设备规模**   | ≥1亿 Agent  | 支持的最大终端设备数量              |
| **令牌颁发延迟** | ≤50ms（P99） | 从请求到返回 Access Token 的时延  |
| **系统可用性**  | ≥99.99%    | 年度服务不可用时间 ≤52.56分钟       |
| **令牌吊销时效** | ≤1秒        | Refresh Token 吊销后的全局生效时间 |
| **密钥轮换周期** | 30-90天     | 租户 JWT 签名密钥的自动轮换间隔       |

---

## 2. 领域问题全景

### 2.1 核心挑战矩阵

```mermaid
graph TB
    subgraph CP[核心挑战（Core Problems）]
        direction TB
        CP1[身份信任问题<br/>（Identity Trust）]
        CP2[性能与规模挑战<br/>（Performance & Scale）]
        CP3[安全风险防御<br/>（Security Risks）]
        CP4[运维复杂度<br/>（Operational Complexity）]
    end
    
    subgraph CP1D[身份信任问题详细]
        direction LR
        T1[漫游 Agent 身份可信度]
        T2[凭证生命周期管理]
        T3[多租户密钥安全隔离]
    end
    
    subgraph CP2D[性能与规模挑战详细]
        direction LR
        S1[百万并发令牌请求]
        S2[亿级设备 Agent 管理]
        S3[全球低延迟访问]
    end
    
    subgraph CP3D[安全风险防御详细]
        direction LR
        R1[凭证泄露与滥用]
        R2[中间人攻击]
        R3[重放攻击]
        R4[内部威胁]
    end
    
    CP1 --> CP1D
    CP2 --> CP2D
    CP3 --> CP3D
    
    style CP fill:#ffe6e6
    style CP1D fill:#fff4e6
    style CP2D fill:#e6f3ff
    style CP3D fill:#ffe6f0
```

### 2.2 身份信任问题

#### 2.2.1 漫游 Agent 身份可信度保障

**问题描述**：终端 Agent 在公网环境下漫游，需要持续证明其身份的合法性，且不受网络环境变化、中间人攻击等因素影响。

**挑战要点**：

* 如何在设备首次注册时建立初始信任根？
* 如何在漫游过程中持续验证设备身份？
* 如何防止设备指纹伪造或克隆？

#### 2.2.2 凭证生命周期管理

**问题描述**：Refresh Token 和 Access Token 的生命周期需要精细化管理，既要保证安全性（防止长期有效令牌被滥用），又要保证用户体验（避免频繁重新认证）。

**挑战要点**：

* Refresh Token 的有效期设计（长期 vs 短期）
* Access Token 的刷新策略（主动 vs 被动）
* 令牌吊销的实时性与全局一致性
* 一次性使用令牌（One-Time Token）的实现

#### 2.2.3 多租户密钥安全隔离

**问题描述**：系统需要支持数千甚至数万租户，每个租户的 JWT 签名密钥必须独立管理和隔离，防止交叉泄露。

**挑战要点**：

* 密钥的集中存储与安全访问
* 密钥的自动轮换与版本管理
* 密钥泄露后的快速响应机制

### 2.3 性能与规模挑战

#### 2.3.1 百万并发令牌请求

**问题描述**：在特定场景下（如设备集中上线、定时策略更新），可能在短时间内产生百万级 QPS 的令牌请求。

**技术难点**：

* 认证服务的瓶颈识别与优化
* 数据库与缓存的压力分散
* 热点数据的访问优化

#### 2.3.2 亿级设备 Agent 管理

**问题描述**：系统需要支持亿级规模的设备注册、凭证管理和访问控制。

**技术难点**：

* 海量数据的存储与查询优化
* 分布式缓存的数据分片与一致性
* 全局唯一标识符（Agent ID、JTI）的生成策略

#### 2.3.3 全球低延迟访问

**问题描述**：终端 Agent 分布在全球各地,需要就近访问认证服务以降低延迟。

**技术难点**：

* 多区域部署的架构设计
* 跨区域数据同步的时效性
* 全球负载均衡与流量调度

### 2.4 安全风险防御

#### 2.4.1 凭证泄露与滥用

**风险描述**：Refresh Token 或 Access Token 被窃取后，攻击者可以冒充合法 Agent 访问业务资源。

**防御要求**：

* Refresh Token 的加密存储与传输
* Access Token 的短生命周期设计
* 令牌黑名单的实时同步

#### 2.4.2 中间人攻击（MITM）

**风险描述**：攻击者在 Agent 与认证服务之间进行流量劫持，窃取凭证或篡改数据。

**防御要求**：

* 全链路 TLS 加密
* 双向 TLS 认证（mTLS）
* 证书固定（Certificate Pinning）

#### 2.4.3 重放攻击

**风险描述**：攻击者截获合法请求后重复发送，试图绕过认证。

**防御要求**：

* JWT 的唯一标识符（JTI）机制
* 时间戳验证与时间窗口限制
* 一次性令牌设计

#### 2.4.4 内部威胁

**风险描述**：MGR 服务被攻陷后，可能批量滥发 Refresh Token。

**防御要求**：

* MGR 凭证的短效化与动态生成
* MGR 行为的审计与异常检测
* 基于速率限制的防护

---

## 3. 解决方案全景

### 3.1 总体架构原则

```mermaid
graph LR
    subgraph AP[架构原则（Architecture Principles）]
        direction TB
        P1[极简先进<br/>（Simplicity & Modernity）]
        P2[极致并发<br/>（Extreme Concurrency）]
        P3[高可用<br/>（High Availability）]
        P4[全面安全<br/>（Comprehensive Security）]
        P5[逐步演进<br/>（Progressive Evolution）]
    end
    
    subgraph DP[设计模式（Design Patterns）]
        direction TB
        D1[无状态服务<br/>（Stateless Services）]
        D2[分层架构<br/>（Layered Architecture）]
        D3[领域驱动设计<br/>（DDD）]
        D4[面向接口编程<br/>（Interface-Oriented）]
    end
    
    subgraph TP[技术策略（Technical Strategies）]
        direction TB
        T1[双令牌机制<br/>（Dual-Token）]
        T2[JWT 本地验签<br/>（Local Validation）]
        T3[多级缓存<br/>（Multi-Level Cache）]
        T4[异步处理<br/>（Async Processing）]
    end
    
    AP --> DP
    DP --> TP
    
    style AP fill:#e6ffe6
    style DP fill:#e6f3ff
    style TP fill:#fff4e6
```

### 3.2 核心解决策略

#### 3.2.1 双令牌机制（Dual-Token Mechanism）

**设计理念**：通过 Refresh Token 和 Access Token 的分离，实现安全性与性能的平衡。

**Refresh Token 特性**：

* 长效凭证（建议 30-90 天，而非 365 天）
* 加密存储在终端设备的安全区域
* 仅用于获取 Access Token，不直接访问业务资源
* 支持一次性使用（颁发新令牌后旧令牌立即失效）

**Access Token 特性**：

* 短效凭证（5-15 分钟）
* 存储在内存中，不持久化
* 自包含（Self-contained），业务服务可本地验签
* 包含授权信息（scope、tenant_id、agent_id 等）

**优势**：

* Refresh Token 泄露风险窗口大幅缩短
* Access Token 泄露影响有限（短生命周期）
* 业务服务无需频繁回源认证中心

#### 3.2.2 JWT 本地验签（Local Validation）

**设计理念**：将令牌验证的压力从认证中心分散到各业务服务，实现去中心化验证。

**实现机制**：

1. 认证中心使用租户私钥签发 JWT Access Token
2. 业务服务从认证中心获取租户公钥（支持缓存）
3. 业务服务使用公钥在本地验证 Access Token 的签名和有效期
4. 验证通过后,根据 Token 中的 scope 执行权限控制

**优势**：

* 认证中心仅处理令牌颁发，验证压力分散
* 业务服务响应延迟大幅降低（无需网络往返）
* 支持亿级 Agent 的高并发访问

#### 3.2.3 多级缓存架构（Multi-Level Cache）

**设计理念**：通过 L1（本地内存）+ L2（Redis 集群）的多级缓存，最大化减少对后端数据库的访问。

**缓存策略**：

| 数据类型    | L1 缓存 | L2 缓存 | 数据库 | TTL     |
| :------ | :---- | :---- | :-- | :------ |
| 租户公钥    | 是     | 是     | 是   | 1-4 小时  |
| 令牌黑名单   | 否     | 是     | 是   | 根据令牌有效期 |
| 速率限制计数器 | 否     | 是     | 否   | 1 分钟    |
| MGR 凭证  | 否     | 是     | 是   | 1 小时    |

**优势**：

* L1 缓存（进程内存）：零网络延迟，适合热点数据
* L2 缓存（Redis）：亚毫秒级延迟，支持分布式共享
* 数据库：持久化存储，保障数据可靠性

#### 3.2.4 一次性 Refresh Token（One-Time Token）

**设计理念**：每次使用 Refresh Token 获取 Access Token 后，旧 Refresh Token 立即失效，并颁发新的 Refresh Token。

**实现流程**：

1. Agent 使用 Refresh Token A 请求 Access Token
2. 认证中心验证 Refresh Token A 的合法性
3. 认证中心颁发 Access Token 和新的 Refresh Token B
4. 认证中心将 Refresh Token A 的 JTI 加入黑名单
5. Agent 存储新的 Refresh Token B，丢弃旧令牌

**优势**：

* 防止 Refresh Token 重放攻击
* 缩短令牌泄露的影响窗口
* 提升整体安全性

### 3.3 安全增强策略

#### 3.3.1 设备指纹与信任等级

**设计理念**：引入设备指纹（Device Fingerprint）作为 Agent 身份的辅助验证手段，并根据信任等级动态调整访问策略。

**设备指纹组成**：

* 硬件特征（CPU ID、MAC 地址、设备序列号等）
* 软件特征（操作系统版本、应用签名等）
* 行为特征（登录位置、时间模式等）

**信任等级模型**：

| 信任等级 | 设备特征              | 令牌有效期  | 访问范围   |
| :--- | :---------------- | :----- | :----- |
| 高信任  | TPM/TEE 绑定 + 硬件指纹 | 标准     | 完整业务访问 |
| 中信任  | 软件指纹 + 行为模式       | 缩短 50% | 受限业务访问 |
| 低信任  | 基础识别              | 缩短 75% | 仅基础功能  |
| 不信任  | 异常行为检测            | 立即吊销   | 拒绝访问   |

#### 3.3.2 MGR 双向认证与行为审计

**设计理念**：强化 MGR 与认证中心之间的信任关系，防止 MGR 被攻陷后的批量滥用。

**双向认证机制**：

* MGR 使用 Client Assertion（JWT + 私钥签名）代替静态 Secret
* 认证中心验证 MGR 的客户端证书（mTLS）
* 每个 MGR 实例具有独立的密钥对和证书

**行为审计策略**：

* 记录 MGR 的所有设备注册请求
* 监控 MGR 的注册频率和模式
* 检测异常行为（如短时间内大量注册）
* 支持基于规则的自动告警与限流

#### 3.3.3 动态上下文访问控制（Context-Aware Access）

**设计理念**：在令牌验证的基础上，引入实时上下文信号（地理位置、设备健康态、网络环境等）进行动态授权决策。

**上下文信号**：

* 地理位置（IP 地理定位、GPS 坐标）
* 设备健康态（病毒扫描状态、系统更新状态）
* 网络环境（公网 vs 内网、VPN 状态）
* 时间模式（工作时间 vs 非工作时间）

**决策逻辑**：

```mermaid
graph TD
    A[令牌验证通过] --> B{上下文信号评估}
    B -->|全部合规| C[授予完整权限]
    B -->|部分异常| D[降级访问权限]
    B -->|严重异常| E[拒绝访问并告警]
    
    style A fill:#e6ffe6
    style C fill:#e6ffe6
    style D fill:#fff4e6
    style E fill:#ffe6e6
```

---

## 4. 系统架构设计

### 4.1 总体架构图

```mermaid
graph TB
    subgraph EXT[外部交互层（External Interaction Layer）]
        direction LR
        AGT[终端 Agent<br/>（Agent）]
        MGR[内网管理器<br/>（MGR）]
        IS[情报服务<br/>（Intelligence Service）]
        ADMIN[管理员工具<br/>（Admin Tools）]
    end
    
    subgraph API[API 网关层（API Gateway Layer）]
        direction TB
        LB[负载均衡器<br/>（Load Balancer）]
        GW[API 网关<br/>（API Gateway）<br/>认证、限流、路由]
    end
    
    subgraph APP[应用服务层（Application Service Layer）]
        direction TB
        AUTH[认证服务<br/>（Auth Service）<br/>设备注册、令牌颁发]
        TOKEN[令牌服务<br/>（Token Service）<br/>JWT 生成与验证]
        REVOKE[吊销服务<br/>（Revocation Service）<br/>黑名单管理]
        POLICY[策略服务<br/>（Policy Service）<br/>权限决策]
    end
    
    subgraph DOMAIN[领域服务层（Domain Service Layer）]
        direction TB
        KEYMGMT[密钥管理<br/>（Key Management）<br/>密钥获取与轮换]
        AUDIT[审计服务<br/>（Audit Service）<br/>日志记录]
        DEVICE[设备管理<br/>（Device Management）<br/>设备指纹、信任等级]
    end
    
    subgraph INFRA[基础设施层（Infrastructure Layer）]
        direction LR
        VAULT[密钥库<br/>（Vault）<br/>密钥存储]
        REDIS[缓存<br/>（Redis Cluster）<br/>黑名单、公钥缓存]
        POSTGRES[数据库<br/>（PostgreSQL HA）<br/>租户配置、审计日志]
        KAFKA[消息队列<br/>（Kafka）<br/>异步审计]
    end
    
    subgraph OBS[可观测性层（Observability Layer）]
        direction LR
        PROM[Prometheus<br/>指标监控]
        LOKI[Loki<br/>日志聚合]
        JAEGER[Jaeger<br/>分布式追踪]
    end
    
    EXT -->|HTTPS| LB
    LB --> GW
    GW --> APP
    APP --> DOMAIN
    DOMAIN --> INFRA
    
    APP -.->|指标、日志、追踪| OBS
    DOMAIN -.->|指标、日志、追踪| OBS
    
    style EXT fill:#e6f3ff
    style API fill:#e6ffe6
    style APP fill:#fff4e6
    style DOMAIN fill:#ffe6f0
    style INFRA fill:#f0e6ff
    style OBS fill:#ffe6e6
```

### 4.2 分层职责说明

#### 4.2.1 外部交互层（External Interaction Layer）

**职责**：

* 终端 Agent：设备注册、令牌获取与刷新、业务访问
* 内网管理器（MGR）：代理 Agent 进行设备注册、凭证下发
* 情报服务：业务资源访问控制（PEP）
* 管理员工具：租户管理、密钥轮换、令牌吊销等运维操作

#### 4.2.2 API 网关层（API Gateway Layer）

**职责**：

* 负载均衡：跨多个服务实例的流量分发
* 认证鉴权：验证调用方身份（mTLS、API Key 等）
* 速率限制：全局、租户、Agent 三级限流
* 请求路由：根据 API 路径将请求转发到对应服务

**技术选型**：

* Kubernetes Ingress + NGINX Ingress Controller
* 或 Envoy + Istio Service Mesh

#### 4.2.3 应用服务层（Application Service Layer）

**职责**：

* **认证服务（Auth Service）**：

  * 处理设备注册请求（/api/v1/auth/register-device）
  * 处理令牌颁发请求（/api/v1/auth/token）
  * 验证 MGR 凭证、Refresh Token 合法性
* **令牌服务（Token Service）**：

  * JWT 的生成、签名、验证
  * 公钥分发（/api/v1/auth/public-key/{tenant_id}）
  * 令牌内省（/api/v1/auth/introspect）
* **吊销服务（Revocation Service）**：

  * 令牌黑名单的添加、查询、清理
  * 吊销请求处理（/api/v1/auth/revoke）
* **策略服务（Policy Service）**：

  * 权限策略的加载与评估
  * 基于 ABAC 的授权决策
  * Scope 的动态计算

#### 4.2.4 领域服务层（Domain Service Layer）

**职责**：

* **密钥管理（Key Management）**：

  * 从 Vault 获取租户私钥用于 JWT 签名
  * 公钥的缓存与版本管理
  * 密钥轮换的触发与协调
* **审计服务（Audit Service）**：

  * 记录所有认证授权事件
  * 异步发送审计日志到 Kafka
  * 支持日志的结构化与索引
* **设备管理（Device Management）**：

  * 设备指纹的生成与验证
  * 设备信任等级的评估
  * 设备状态的持久化

#### 4.2.5 基础设施层（Infrastructure Layer）

**组件说明**：

| 组件                | 作用                   | 数据类型              | 持久化   |
| :---------------- | :------------------- | :---------------- | :---- |
| **Vault**         | JWT 签名密钥、加密密钥的集中存储   | 密钥对（RSA 4096）     | 是     |
| **Redis Cluster** | 令牌黑名单、公钥缓存、速率限制计数器   | KV、Set、Sorted Set | 否（内存） |
| **PostgreSQL HA** | 租户配置、策略规则、审计日志、设备元数据 | 关系型数据             | 是     |
| **Kafka**         | 异步审计日志、事件总线          | 消息流               | 可配置   |

### 4.3 数据流图

```mermaid
sequenceDiagram
    participant A as 终端 Agent
    participant M as 内网 MGR
    participant G as API 网关
    participant AS as 认证服务
    participant TS as 令牌服务
    participant KM as 密钥管理
    participant V as Vault
    participant R as Redis
    participant P as PostgreSQL
    participant IS as 情报服务
    
    rect rgb(230, 255, 230)
        note over A,P: 阶段1：设备注册与 Refresh Token 颁发
        A->>+M: 1.1 设备注册请求<br/>（tenantID, deviceInfo）
        M->>+G: 1.2 代理注册请求<br/>（MgrClientID, MgrSecret, tenantID, agentID）
        G->>+AS: 1.3 路由到认证服务
        AS->>AS: 1.4 验证 MGR 凭证
        AS->>+P: 1.5 查询租户配置
        P-->>-AS: 1.6 返回租户配置
        AS->>+KM: 1.7 获取租户私钥
        KM->>+V: 1.8 请求私钥
        V-->>-KM: 1.9 返回私钥
        KM-->>-AS: 1.10 返回私钥
        AS->>+TS: 1.11 生成 Refresh Token
        TS->>TS: 1.12 签名 JWT
        TS-->>-AS: 1.13 返回 Refresh Token
        AS->>+P: 1.14 存储 Refresh Token 元数据
        P-->>-AS: 1.15 确认
        AS-->>-G: 1.16 返回 Refresh Token
        G-->>-M: 1.17 返回 Refresh Token
        M-->>-A: 1.18 安全下发 Refresh Token
    end
    
    rect rgb(230, 243, 255)
        note over A,IS: 阶段2：Access Token 获取与业务访问
        A->>+G: 2.1 请求 Access Token<br/>（Refresh Token）
        G->>+AS: 2.2 路由到认证服务
        AS->>+R: 2.3 检查 Refresh Token 黑名单
        R-->>-AS: 2.4 返回检查结果（未吊销）
        AS->>+TS: 2.5 验证 Refresh Token
        TS->>+KM: 2.6 获取租户公钥
        KM->>+R: 2.7 查询公钥缓存
        R-->>-KM: 2.8 返回公钥（或未命中）
        alt 缓存未命中
            KM->>+V: 2.9 请求公钥
            V-->>-KM: 2.10 返回公钥
            KM->>+R: 2.11 缓存公钥
            R-->>-KM: 2.12 确认
        end
        KM-->>-TS: 2.13 返回公钥
        TS->>TS: 2.14 验签 Refresh Token
        TS-->>-AS: 2.15 验证通过
        AS->>+TS: 2.16 生成 Access Token
        TS->>TS: 2.17 签名 JWT
        TS-->>-AS: 2.18 返回 Access Token
        AS-->>-G: 2.19 返回 Access Token
        G-->>-A: 2.20 返回 Access Token
        
        A->>+IS: 2.21 业务请求<br/>（Authorization: Bearer <Access Token>）
        IS->>+KM: 2.22 获取租户公钥（缓存）
        KM-->>-IS: 2.23 返回公钥
        IS->>IS: 2.24 本地验签 Access Token
        IS->>IS: 2.25 权限决策（基于 scope）
        IS-->>-A: 2.26 返回业务数据
    end
```

---

## 5. 核心组件详细设计

### 5.1 认证服务（Auth Service）

#### 5.1.1 职责边界

* **设备注册管理**：处理 MGR 代理的设备注册请求，验证 MGR 凭证，生成并返回 Refresh Token
* **令牌颁发**：验证 Refresh Token 合法性，颁发短效 Access Token
* **凭证验证**：验证 MGR Client Assertion、Refresh Token 的签名、有效期、吊销状态
* **速率限制执行**：基于租户、MGR、Agent 三级限流策略
* **审计日志记录**：所有认证事件的结构化日志输出

#### 5.1.2 核心接口设计

**5.1.2.1 设备注册接口**

```http
POST /api/v1/auth/register-device
Content-Type: application/x-www-form-urlencoded

client_id={mgr_client_id}&
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&
client_assertion={mgr_jwt_assertion}&
grant_type=client_credentials&
tenant_id={tenant_id}&
agent_id={agent_id}&
device_fingerprint={fingerprint_hash}
```

**请求参数**：

| 参数                      | 类型     | 必填 | 说明                                                              |
| :---------------------- | :----- | :- | :-------------------------------------------------------------- |
| client_id              | string | 是  | MGR 的客户端标识符                                                     |
| client_assertion_type | string | 是  | 固定值：urn:ietf:params:oauth:client-assertion-type:jwt-bearer |
| client_assertion       | string | 是  | MGR 使用私钥签名的 JWT                                                 |
| grant_type             | string | 是  | 固定值：client_credentials                                         |
| tenant_id              | string | 是  | 租户标识符                                                           |
| agent_id               | string | 是  | 终端 Agent 唯一标识符                                                  |
| device_fingerprint     | string | 否  | 设备指纹哈希值                                                         |

**MGR Client Assertion JWT 结构**：

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "mgr-key-001"
  },
  "payload": {
    "iss": "mgr-client-id-12345",
    "sub": "mgr-client-id-12345",
    "aud": "https://auth.cloudbrain.cert/api/v1/auth",
    "iat": 1698123456,
    "exp": 1698123516,
    "jti": "unique-request-id-001"
  }
}
```

**成功响应（200 OK）**：

```json
{
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAxIn0...",
  "token_type": "Bearer",
  "expires_in": 7776000,
  "scope": "agent:read agent:write"
}
```

**错误响应示例**：

```json
{
  "error": "invalid_client",
  "error_description": "MGR client assertion signature verification failed",
  "error_uri": "https://docs.cloudbrain.cert/errors#invalid_client"
}
```

**5.1.2.2 令牌颁发接口**

```http
POST /api/v1/auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token={refresh_token}&
scope={requested_scope}
```

**请求参数**：

| 参数             | 类型     | 必填 | 说明                       |
| :------------- | :----- | :- | :----------------------- |
| grant_type    | string | 是  | 固定值：refresh_token       |
| refresh_token | string | 是  | 设备持有的 Refresh Token      |
| scope          | string | 否  | 请求的权限范围（可选，默认继承原有 scope） |

**成功响应（200 OK）**：

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAxIn0...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAyIn0...",
  "scope": "agent:read agent:write"
}
```

**注意**：响应中包含新的 Refresh Token（一次性令牌机制），旧 Refresh Token 已失效。

#### 5.1.3 业务流程设计

**5.1.3.1 设备注册流程**

```mermaid
flowchart TD
    A[接收注册请求] --> B{验证 MGR Client Assertion}
    B -->|失败| C[返回 invalid_client 错误]
    B -->|成功| D{检查 MGR 速率限制}
    D -->|超限| E[返回 429 Too Many Requests]
    D -->|通过| F{验证租户配置}
    F -->|租户不存在/禁用| G[返回 invalid_request 错误]
    F -->|通过| H{检查 Agent ID 冲突}
    H -->|已注册| I{检查设备指纹}
    I -->|匹配| J[返回已存在的 Refresh Token]
    I -->|不匹配| K[记录异常并拒绝]
    H -->|未注册| L[生成设备元数据]
    L --> M[获取租户私钥]
    M --> N[生成 Refresh Token JWT]
    N --> O[存储 Token 元数据到数据库]
    O --> P[记录审计日志]
    P --> Q[返回 Refresh Token]
    
    style A fill:#e6f3ff
    style C fill:#ffe6e6
    style E fill:#ffe6e6
    style G fill:#ffe6e6
    style K fill:#ffe6e6
    style Q fill:#e6ffe6
```

**5.1.3.2 令牌颁发流程**

```mermaid
flowchart TD
    A[接收 Token 请求] --> B{检查 Refresh Token 黑名单}
    B -->|已吊销| C[返回 invalid_grant 错误]
    B -->|未吊销| D{验证 Refresh Token 签名}
    D -->|失败| E[返回 invalid_grant 错误]
    D -->|成功| F{检查 Token 有效期}
    F -->|过期| G[返回 invalid_grant 错误]
    F -->|有效| H{检查 Agent 速率限制}
    H -->|超限| I[返回 429 Too Many Requests]
    H -->|通过| J[获取租户私钥]
    J --> K[生成 Access Token JWT]
    K --> L[生成新的 Refresh Token JWT]
    L --> M[将旧 Refresh Token 加入黑名单]
    M --> N[更新 Token 元数据]
    N --> O[记录审计日志]
    O --> P[返回 Access Token 和新 Refresh Token]
    
    style A fill:#e6f3ff
    style C fill:#ffe6e6
    style E fill:#ffe6e6
    style G fill:#ffe6e6
    style I fill:#ffe6e6
    style P fill:#e6ffe6
```

#### 5.1.4 关键实现细节

**5.1.4.1 MGR Client Assertion 验证**

```go
// 伪代码示例
func VerifyMgrClientAssertion(assertion string, clientID string) error {
    // 1. 解析 JWT 头部获取 kid
    header, err := ParseJWTHeader(assertion)
    if err != nil {
        return ErrInvalidAssertion
    }
    
    // 2. 从密钥管理获取 MGR 公钥
    publicKey, err := keyMgmt.GetMgrPublicKey(clientID, header.Kid)
    if err != nil {
        return ErrKeyNotFound
    }
    
    // 3. 验证签名
    claims, err := jwt.Verify(assertion, publicKey)
    if err != nil {
        return ErrInvalidSignature
    }
    
    // 4. 验证标准声明
    if claims.Issuer != clientID || claims.Subject != clientID {
        return ErrInvalidClaims
    }
    
    if claims.Audience != config.AuthServiceURL {
        return ErrInvalidAudience
    }
    
    // 5. 验证时间窗口（防重放）
    now := time.Now().Unix()
    if now < claims.IssuedAt || now > claims.ExpiresAt {
        return ErrExpiredAssertion
    }
    
    // 6. 验证 JTI 唯一性（防重放）
    exists, err := redis.Exists(ctx, "jti:"+claims.JTI)
    if err != nil || exists {
        return ErrDuplicateJTI
    }
    
    // 7. 缓存 JTI（TTL = exp - iat）
    redis.SetEx(ctx, "jti:"+claims.JTI, "1", time.Duration(claims.ExpiresAt-claims.IssuedAt)*time.Second)
    
    return nil
}
```

**5.1.4.2 Refresh Token 生成**

```go
func GenerateRefreshToken(tenantID, agentID string, scope []string) (string, error) {
    // 1. 生成唯一 JTI
    jti := uuid.New().String()
    
    // 2. 设置 Token 声明
    now := time.Now().Unix()
    claims := jwt.Claims{
        Issuer:    "cbc-auth-service",
        Subject:   agentID,
        Audience:  []string{config.AuthServiceURL},
        ExpiresAt: now + config.RefreshTokenTTL, // 默认 30 天
        NotBefore: now,
        IssuedAt:  now,
        JTI:       jti,
        Custom: map[string]interface{}{
            "tenant_id": tenantID,
            "scope":     strings.Join(scope, " "),
            "type":      "refresh_token",
        },
    }
    
    // 3. 获取租户私钥
    privateKey, keyID, err := keyMgmt.GetTenantPrivateKey(tenantID)
    if err != nil {
        return "", err
    }
    
    // 4. 签名 JWT
    token, err := jwt.Sign(claims, privateKey, keyID)
    if err != nil {
        return "", err
    }
    
    // 5. 存储 Token 元数据（用于吊销和审计）
    metadata := TokenMetadata{
        JTI:       jti,
        TenantID:  tenantID,
        AgentID:   agentID,
        Type:      "refresh_token",
        ExpiresAt: time.Unix(claims.ExpiresAt, 0),
        CreatedAt: time.Now(),
    }
    
    err = db.InsertTokenMetadata(ctx, metadata)
    if err != nil {
        return "", err
    }
    
    return token, nil
}
```

**5.1.4.3 Refresh Token 黑名单检查**

```go
func IsRefreshTokenRevoked(jti string) (bool, error) {
    // 1. 查询 Redis 黑名单
    exists, err := redis.SIsMember(ctx, "revoked_tokens", jti)
    if err != nil {
        // Redis 故障时降级到数据库查询
        return db.IsTokenRevoked(ctx, jti)
    }
    
    return exists, nil
}

func RevokeRefreshToken(jti string, expiresAt time.Time) error {
    // 1. 添加到 Redis 黑名单
    err := redis.SAdd(ctx, "revoked_tokens", jti)
    if err != nil {
        return err
    }
    
    // 2. 设置过期时间（Token 过期后自动清理）
    ttl := time.Until(expiresAt)
    redis.Expire(ctx, "revoked_tokens", ttl)
    
    // 3. 持久化到数据库（冗余保障）
    return db.RevokeToken(ctx, jti, expiresAt)
}
```

---

### 5.2 令牌服务（Token Service）

#### 5.2.1 职责边界

* **JWT 生成与签名**：使用租户私钥生成标准 JWT Access Token 和 Refresh Token
* **JWT 验证与解析**：验证 JWT 签名、标准声明（exp、nbf、iat 等）
* **公钥分发**：为业务服务提供租户公钥查询接口
* **令牌内省**：为不支持本地验签的业务服务提供令牌验证接口

#### 5.2.2 核心接口设计

**5.2.2.1 公钥查询接口**

```http
GET /api/v1/auth/public-key/{tenant_id}?kid={key_id}
```

**成功响应（200 OK）**：

```json
{
  "tenant_id": "tenant-12345",
  "keys": [
    {
      "kid": "tenant-key-001",
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...",
      "e": "AQAB",
      "x5c": ["MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNV..."]
    }
  ]
}
```

**5.2.2.2 令牌内省接口（可选）**

```http
POST /api/v1/auth/introspect
Content-Type: application/x-www-form-urlencoded

token={access_token}&
token_type_hint=access_token
```

**成功响应（200 OK）**：

```json
{
  "active": true,
  "scope": "agent:read agent:write",
  "client_id": "agent-67890",
  "tenant_id": "tenant-12345",
  "exp": 1698124356,
  "iat": 1698123456,
  "sub": "agent-67890",
  "jti": "unique-token-id-002"
}
```

#### 5.2.3 Access Token 结构设计

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "tenant-key-001"
  },
  "payload": {
    "iss": "cbc-auth-service",
    "sub": "agent-67890",
    "aud": ["https://intelligence.service"],
    "exp": 1698124356,
    "nbf": 1698123456,
    "iat": 1698123456,
    "jti": "unique-token-id-002",
    "tenant_id": "tenant-12345",
    "scope": "agent:read agent:write intelligence:query",
    "device_trust_level": "high",
    "azp": "cbc-auth-service"
  }
}
```

**Claims 说明**：

| Claim                | 类型     | 说明                      |
| :------------------- | :----- | :---------------------- |
| iss                  | string | 令牌颁发者（cbc-auth-service） |
| sub                  | string | 主体标识符（Agent ID）         |
| aud                  | array  | 令牌接收方（业务服务列表）           |
| exp                  | int    | 过期时间戳（Unix 时间）          |
| nbf                  | int    | 生效时间戳                   |
| iat                  | int    | 颁发时间戳                   |
| jti                  | string | JWT 唯一标识符               |
| tenant_id           | string | 租户标识符                   |
| scope                | string | 权限范围（空格分隔）              |
| device_trust_level | string | 设备信任等级（high/medium/low） |
| azp                  | string | 授权方（Authorized Party）   |

---

### 5.3 密钥管理服务（Key Management Service）

#### 5.3.1 职责边界

* **密钥获取**：从 Vault 获取租户的 JWT 签名密钥对（私钥/公钥）
* **密钥缓存**：在内存和 Redis 中缓存公钥，减少 Vault 访问压力
* **密钥轮换**：定期触发租户密钥的自动轮换，并管理密钥版本
* **密钥版本管理**：支持多版本密钥共存（旧版本用于验证，新版本用于签名）

#### 5.3.2 密钥存储结构

**Vault 路径设计**：

```
/secret/cbc/tenants/{tenant_id}/keys/{key_id}
```

**密钥元数据**：

```json
{
  "key_id": "tenant-key-001",
  "tenant_id": "tenant-12345",
  "algorithm": "RS256",
  "key_size": 4096,
  "private_key": "-----BEGIN RSA PRIVATE KEY-----nMIIJK...",
  "public_key": "-----BEGIN PUBLIC KEY-----nMIICIj...",
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2024-04-01T00:00:00Z",
  "status": "active"
}
```

#### 5.3.3 密钥轮换策略

**轮换触发条件**：

1. 定期轮换：每 30-90 天自动触发
2. 紧急轮换：密钥泄露事件后手动触发
3. 合规要求：满足特定行业的密钥管理规范

**轮换流程**：

```mermaid
flowchart TD
    A[触发密钥轮换] --> B[生成新密钥对]
    B --> C[存储新密钥到 Vault]
    C --> D[标记新密钥为 active]
    D --> E[标记旧密钥为 deprecated]
    E --> F[更新 Redis 公钥缓存]
    F --> G[发送轮换通知]
    G --> H{等待过渡期}
    H -->|30 天后| I[标记旧密钥为 revoked]
    I --> J[清理旧密钥缓存]
    J --> K[完成轮换]
    
    style A fill:#e6f3ff
    style K fill:#e6ffe6
```

**密钥状态转换**：

```mermaid
stateDiagram-v2
    [*] --> active: 密钥创建
    active --> deprecated: 新密钥生成
    deprecated --> revoked: 过渡期结束
    revoked --> [*]: 密钥删除
    
    note right of active: 用于签名和验证
    note right of deprecated: 仅用于验证
    note right of revoked: 禁止使用
```

---

### 5.4 吊销服务（Revocation Service）

#### 5.4.1 职责边界

* **令牌吊销**：处理 Refresh Token 和 Access Token 的吊销请求
* **黑名单管理**：维护令牌黑名单的添加、查询、清理
* **吊销传播**：确保吊销事件在全局范围内快速生效

#### 5.4.2 核心接口设计

**吊销接口**：

```http
POST /api/v1/auth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer {admin_token}

token={refresh_token}&
token_type_hint=refresh_token
```

**成功响应（200 OK）**：

```json
{
  "revoked": true,
  "jti": "unique-token-id-001",
  "revoked_at": "2024-10-23T10:30:00Z"
}
```

#### 5.4.3 黑名单实现策略

**多级黑名单设计**：

```mermaid
graph TD
    A[吊销请求] --> B[写入 Redis Set]
    B --> C[设置 TTL = Token.exp - now]
    C --> D[异步写入 PostgreSQL]
    D --> E[发送 Kafka 事件]
    E --> F[全局同步]
    
    G[验证请求] --> H{查询 Redis}
    H -->|命中| I[拒绝访问]
    H -->|未命中| J{查询 PostgreSQL}
    J -->|命中| K[更新 Redis + 拒绝]
    J -->|未命中| L[允许访问]
    
    style A fill:#e6f3ff
    style I fill:#ffe6e6
    style K fill:#ffe6e6
    style L fill:#e6ffe6
```

---

## 6. 关键业务场景详细设计

### 6.1 场景一：海量设备集中上线

**场景描述**：
在特定时间窗口（如凌晨策略推送），可能有数百万终端 Agent 同时启动并请求 Access Token。

**技术挑战**：

* 瞬时 QPS 达到 100 万+
* 数据库连接池耗尽
* Redis 热点 Key 问题

**解决方案**：

#### 6.1.1 请求削峰与限流

```mermaid
graph LR
    A[Agent 请求] --> B{全局限流}
    B -->|通过| C{租户限流}
    C -->|通过| D{Agent 限流}
    D -->|通过| E[处理请求]
    B -->|拒绝| F[返回 429 + Retry-After]
    C -->|拒绝| F
    D -->|拒绝| F
    
    style F fill:#ffe6e6
```

**限流算法**：令牌桶（Token Bucket）+ 滑动窗口（Sliding Window）

**限流配置**：

| 层级    | 限流阈值          | 时间窗口 | 存储            |
| :---- | :------------ | :--- | :------------ |
| 全局    | 1,000,000 QPS | 1 秒  | Redis Cluster |
| 租户    | 100,000 QPS   | 1 秒  | Redis Cluster |
| Agent | 10 QPS        | 1 分钟 | Redis Cluster |

#### 6.1.2 数据库访问优化

**策略**：

1. **读写分离**：令牌验证只读副本，令牌颁发写主库
2. **批量写入**：聚合审计日志后批量写入数据库
3. **异步落库**：令牌元数据先写 Redis，异步同步到 PostgreSQL

#### 6.1.3 Redis 热点 Key 优化

**问题**：租户公钥作为热点 Key，单分片 QPS 过高。

**解决方案**：本地缓存（L1） + Redis 缓存（L2）

```go
// 伪代码
func GetTenantPublicKey(tenantID string) (*rsa.PublicKey, error) {
    // L1：进程内存缓存（TTL = 1 小时）
    if key, found := l1Cache.Get(tenantID); found {
        return key, nil
    }
    
    // L2：Redis 缓存（TTL = 4 小时）
    if key, err := redis.Get(ctx, "pubkey:"+tenantID); err == nil {
        l1Cache.Set(tenantID, key, 1*time.Hour)
        return key, nil
    }
    
    // L3：从 Vault 加载
    key, err := vault.GetPublicKey(tenantID)
    if err != nil {
        return nil, err
    }
    
    // 回写缓存
    redis.Set(ctx, "pubkey:"+tenantID, key, 4*time.Hour)
    l1Cache.Set(tenantID, key, 1*time.Hour)
    
    return key, nil
}
```

---

### 6.2 场景二：Refresh Token 泄露应急响应

**场景描述**：
检测到某个 Agent 的 Refresh Token 被盗用，需要快速吊销并通知 Agent 重新注册。

**应急流程**：

```mermaid
sequenceDiagram
    participant MON as 监控系统
    participant ADMIN as 管理员
    participant REV as 吊销服务
    participant REDIS as Redis
    participant DB as PostgreSQL
    participant KAFKA as Kafka
    participant AGT as 受影响 Agent
    
    MON->>ADMIN: 1. 异常行为告警<br/>（异地登录、频繁刷新）
    ADMIN->>REV: 2. 吊销 Refresh Token
    REV->>REDIS: 3. 添加到黑名单
    REV->>DB: 4. 持久化吊销记录
    REV->>KAFKA: 5. 发布吊销事件
    KAFKA-->>AGT: 6. 推送吊销通知
    AGT->>AGT: 7. 清除本地凭证
    AGT->>REV: 8. 请求新 Refresh Token（via MGR）
    REV-->>AGT: 9. 返回新凭证
```

**关键指标**：

* 吊销生效时间：≤1 秒（全球同步）
* Agent 重新认证时间：≤10 秒

---

### 6.3 场景三：跨区域部署与就近访问

**场景描述**：
终端 Agent 分布在全球多个地区（如美洲、欧洲、亚太），需要就近访问认证服务以降低延迟。

**架构设计**：

```mermaid
graph TB
    subgraph US[美洲区域]
        LB_US[负载均衡器]
        AUTH_US[认证服务集群]
        REDIS_US[Redis 集群]
    end
    
    subgraph EU[欧洲区域]
        LB_EU[负载均衡器]
        AUTH_EU[认证服务集群]
        REDIS_EU[Redis 集群]
    end
    
    subgraph APAC[亚太区域]
        LB_APAC[负载均衡器]
        AUTH_APAC[认证服务集群]
        REDIS_APAC[Redis 集群]
    end
    
    subgraph GLOBAL[全局共享层]
        VAULT[Vault 主集群]
        PG_PRIMARY[PostgreSQL 主库]
        PG_REPLICA[PostgreSQL 只读副本]
        KAFKA[Kafka 集群]
    end
    
    AGT_US[美洲 Agent] -->|就近访问| LB_US
    AGT_EU[欧洲 Agent] -->|就近访问| LB_EU
    AGT_APAC[亚太 Agent] -->|就近访问| LB_APAC
    
    AUTH_US --> VAULT
    AUTH_EU --> VAULT
    AUTH_APAC --> VAULT
    
    AUTH_US --> PG_REPLICA
    AUTH_EU --> PG_REPLICA
    AUTH_APAC --> PG_REPLICA
    
    AUTH_US -.->|写操作| PG_PRIMARY
    AUTH_EU -.->|写操作| PG_PRIMARY
    AUTH_APAC -.->|写操作| PG_PRIMARY
    
    PG_PRIMARY -.->|复制| PG_REPLICA
    
    REDIS_US -.->|黑名单同步| KAFKA
    REDIS_EU -.->|黑名单同步| KAFKA
    REDIS_APAC -.->|黑名单同步| KAFKA
```

**数据一致性保障**：

* **强一致性数据**（令牌黑名单）：通过 Kafka 事件流同步到所有区域
* **最终一致性数据**（公钥缓存）：允许短暂不一致（TTL 内）
* **全局唯一数据**（JTI）：通过全局 ID 生成器（如 Snowflake 算法）

---

## 7. 技术选型与实现策略

### 7.1 编程语言与框架


| 组件         | 技术选型                 | 理由                     |
| :--------- | :------------------- | :--------------------- |
| **认证服务**   | Go + Gin 框架          | 高性能、并发友好、内存占用低         |
| **令牌服务**   | Go + jwt-go 库        | 成熟的 JWT 实现，支持多种签名算法    |
| **密钥管理服务** | Go + Vault Go Client | 与 HashiCorp Vault 原生集成 |
| **吊销服务**   | Go + go-redis 库      | 高效的 Redis 客户端，支持集群模式   |
| **API 网关** | Kong/Traefik         | 成熟的开源网关，支持插件扩展         |

### 7.2 核心依赖库

#### 7.2.1 JWT 处理

```go
// 推荐库：github.com/golang-jwt/jwt/v5
import (
    "github.com/golang-jwt/jwt/v5"
)

// JWT 签名
func SignJWT(claims jwt.Claims, privateKey *rsa.PrivateKey, keyID string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    token.Header["kid"] = keyID
    return token.SignedString(privateKey)
}

// JWT 验证
func VerifyJWT(tokenString string, publicKey *rsa.PublicKey) (*jwt.Token, error) {
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return publicKey, nil
    })
}
```

#### 7.2.2 限流实现

```go
// 推荐库：golang.org/x/time/rate
import "golang.org/x/time/rate"

// 令牌桶限流器
type RateLimiter struct {
    limiters sync.Map // key: identifier, value: *rate.Limiter
}

func (rl *RateLimiter) Allow(identifier string, rps int) bool {
    limiter, _ := rl.limiters.LoadOrStore(identifier, rate.NewLimiter(rate.Limit(rps), rps))
    return limiter.(*rate.Limiter).Allow()
}
```

#### 7.2.3 Redis 客户端

```go
// 推荐库：github.com/redis/go-redis/v9
import "github.com/redis/go-redis/v9"

// Redis 集群配置
func NewRedisCluster() *redis.ClusterClient {
    return redis.NewClusterClient(&redis.ClusterOptions{
        Addrs: []string{
            "redis-node-1:6379",
            "redis-node-2:6379",
            "redis-node-3:6379",
        },
        PoolSize:     100,
        MinIdleConns: 10,
        MaxRetries:   3,
    })
}
```

### 7.3 存储系统

#### 7.3.1 PostgreSQL 配置

**表结构设计**：

```sql
-- 令牌元数据表
CREATE TABLE token_metadata (
    jti VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(128) NOT NULL,
    token_type VARCHAR(32) NOT NULL, -- 'refresh_token' or 'access_token'
    scope TEXT,
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    device_fingerprint VARCHAR(128),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    INDEX idx_tenant_agent (tenant_id, agent_id),
    INDEX idx_expires_at (expires_at),
    INDEX idx_revoked (revoked_at) WHERE revoked_at IS NOT NULL
);

-- 审计日志表
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL, -- 'register', 'token_issue', 'token_revoke'
    tenant_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(128),
    mgr_client_id VARCHAR(128),
    result VARCHAR(32) NOT NULL, -- 'success', 'failure'
    error_code VARCHAR(64),
    request_id VARCHAR(64),
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    INDEX idx_tenant_time (tenant_id, created_at DESC),
    INDEX idx_event_type (event_type, created_at DESC)
);

-- 租户配置表
CREATE TABLE tenant_configs (
    tenant_id VARCHAR(64) PRIMARY KEY,
    tenant_name VARCHAR(256) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- 'active', 'suspended', 'deleted'
    rate_limit_config JSONB,
    token_ttl_config JSONB,
    key_rotation_policy JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- MGR 配置表
CREATE TABLE mgr_configs (
    mgr_client_id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenant_configs(tenant_id),
    mgr_name VARCHAR(256) NOT NULL,
    public_key_jwks JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    rate_limit_override JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    INDEX idx_tenant (tenant_id)
);
```

**连接池配置**：

```go
import "github.com/jackc/pgx/v5/pgxpool"

func NewPgPool(connString string) (*pgxpool.Pool, error) {
    config, err := pgxpool.ParseConfig(connString)
    if err != nil {
        return nil, err
    }
    
    config.MaxConns = 100
    config.MinConns = 10
    config.MaxConnLifetime = 1 * time.Hour
    config.MaxConnIdleTime = 30 * time.Minute
    
    return pgxpool.NewWithConfig(context.Background(), config)
}
```

#### 7.3.2 Redis 集群配置

**拓扑设计**：3 主 3 从模式

```
Master-1 (slot 0-5460) ---- Slave-1
Master-2 (slot 5461-10922) ---- Slave-2
Master-3 (slot 10923-16383) ---- Slave-3
```

**数据分区策略**：

| 数据类型   | Key 格式                            | 分片策略  | TTL           |
| :----- | :-------------------------------- | :---- | :------------ |
| 黑名单    | `revoked:{jti}`                   | 哈希槽分片 | Token 过期时间    |
| 租户公钥   | `pubkey:{tenant_id}`              | 哈希槽分片 | 4 小时          |
| 限流计数器  | `ratelimit:{scope}:{id}:{window}` | 哈希槽分片 | 时间窗口长度        |
| JTI 去重 | `jti:{jti}`                       | 哈希槽分片 | JWT exp - iat |

#### 7.3.3 Vault 配置

**密钥存储路径**：

```
/secret/
├── cbc/
│   ├── tenants/
│   │   ├── tenant-12345/
│   │   │   ├── keys/
│   │   │   │   ├── tenant-key-001  (active)
│   │   │   │   ├── tenant-key-002  (deprecated)
│   │   │   │   └── metadata.json
│   │   ├── tenant-67890/
│   │   │   └── ...
│   └── mgr/
│       ├── mgr-client-001/
│       │   └── public-keys.json
│       └── ...
```

**访问策略（Policy）**：

```hcl
# 认证服务读取租户密钥
path "secret/data/cbc/tenants/*/keys/*" {
  capabilities = ["read"]
}

# 密钥管理服务创建和轮换密钥
path "secret/data/cbc/tenants/*/keys/*" {
  capabilities = ["create", "read", "update"]
}

# 禁止删除密钥（仅允许标记为 revoked）
path "secret/delete/cbc/tenants/*/keys/*" {
  capabilities = ["deny"]
}
```

---

## 8. 可观测性设计

### 8.1 监控指标

#### 8.1.1 业务指标

| 指标名称                               | 类型        | 说明             | 告警阈值          |
| :--------------------------------- | :-------- | :------------- | :------------ |
| `auth_register_requests_total`     | Counter   | 设备注册请求总数       | N/A           |
| `auth_register_success_total`      | Counter   | 注册成功总数         | N/A           |
| `auth_register_failure_total`      | Counter   | 注册失败总数（按错误码分组） | 增长率 > 10%     |
| `auth_token_issue_requests_total`  | Counter   | 令牌颁发请求总数       | N/A           |
| `auth_token_issue_latency_seconds` | Histogram | 令牌颁发延迟分布       | P99 > 500ms   |
| `auth_token_revoke_total`          | Counter   | 令牌吊销总数         | 突增 > 1000/min |
| `auth_rate_limit_hits_total`       | Counter   | 限流触发次数（按层级分组）  | > 10000/min   |

#### 8.1.2 系统指标

| 指标名称                              | 类型        | 说明               | 告警阈值       |
| :-------------------------------- | :-------- | :--------------- | :--------- |
| `auth_service_cpu_usage_percent`  | Gauge     | CPU 使用率          | > 80%      |
| `auth_service_memory_usage_bytes` | Gauge     | 内存使用量            | > 80% 可用内存 |
| `auth_service_goroutines_total`   | Gauge     | Goroutine 数量     | > 10000    |
| `redis_connection_pool_active`    | Gauge     | Redis 活跃连接数      | > 90% 池容量  |
| `postgres_connection_pool_active` | Gauge     | PostgreSQL 活跃连接数 | > 90% 池容量  |
| `vault_api_latency_seconds`       | Histogram | Vault API 调用延迟   | P95 > 1s   |

#### 8.1.3 Prometheus 指标导出示例

```go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    registerRequests = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "auth_register_requests_total",
            Help: "Total number of device registration requests",
        },
        []string{"tenant_id", "result"}, // labels
    )
    
    tokenIssueLatency = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "auth_token_issue_latency_seconds",
            Help:    "Latency distribution of token issuance",
            Buckets: prometheus.DefBuckets, // [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
        },
        []string{"tenant_id"},
    )
)

// 记录指标
func recordRegisterRequest(tenantID string, success bool) {
    result := "failure"
    if success {
        result = "success"
    }
    registerRequests.WithLabelValues(tenantID, result).Inc()
}

func recordTokenIssueLatency(tenantID string, duration time.Duration) {
    tokenIssueLatency.WithLabelValues(tenantID).Observe(duration.Seconds())
}
```

### 8.2 日志规范

#### 8.2.1 结构化日志格式

```json
{
  "timestamp": "2024-10-23T10:30:45.123Z",
  "level": "INFO",
  "service": "auth-service",
  "instance_id": "auth-pod-001",
  "trace_id": "a1b2c3d4e5f6",
  "span_id": "7890abcd",
  "event_type": "token_issue",
  "tenant_id": "tenant-12345",
  "agent_id": "agent-67890",
  "request_id": "req-unique-001",
  "ip_address": "192.168.1.100",
  "user_agent": "CBCAgent/1.0",
  "result": "success",
  "latency_ms": 45,
  "metadata": {
    "scope": "agent:read agent:write",
    "token_type": "access_token"
  }
}
```

#### 8.2.2 日志级别定义

| 级别        | 使用场景       | 示例                 |
| :-------- | :--------- | :----------------- |
| **DEBUG** | 详细的调试信息    | JWT 解析详情、缓存命中/未命中  |
| **INFO**  | 正常业务操作     | 设备注册成功、令牌颁发成功      |
| **WARN**  | 潜在问题但不影响服务 | 限流触发、缓存失效回退到数据库    |
| **ERROR** | 需要人工介入的错误  | 数据库连接失败、Vault 访问失败 |
| **FATAL** | 服务无法继续运行   | 配置文件缺失、关键依赖不可用     |

#### 8.2.3 Go 日志库配置

```go
import "go.uber.org/zap"

func NewLogger() (*zap.Logger, error) {
    config := zap.NewProductionConfig()
    config.OutputPaths = []string{"stdout", "/var/log/cbc/auth-service.log"}
    config.EncoderConfig.TimeKey = "timestamp"
    config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
    
    return config.Build()
}

// 使用示例
logger.Info("Token issued successfully",
    zap.String("tenant_id", tenantID),
    zap.String("agent_id", agentID),
    zap.Int("latency_ms", latency),
)
```

### 8.3 分布式追踪

#### 8.3.1 OpenTelemetry 集成

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/trace"
)

// 创建 Span
func issueTokenWithTracing(ctx context.Context, req TokenRequest) (TokenResponse, error) {
    tracer := otel.Tracer("auth-service")
    ctx, span := tracer.Start(ctx, "IssueToken")
    defer span.End()
    
    span.SetAttributes(
        attribute.String("tenant_id", req.TenantID),
        attribute.String("agent_id", req.AgentID),
    )
    
    // 验证 Refresh Token
    ctx, childSpan := tracer.Start(ctx, "VerifyRefreshToken")
    err := verifyRefreshToken(ctx, req.RefreshToken)
    childSpan.End()
    if err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, "Token verification failed")
        return TokenResponse{}, err
    }
    
    // 生成 Access Token
    token, err := generateAccessToken(ctx, req)
    if err != nil {
        span.RecordError(err)
        return TokenResponse{}, err
    }
    
    span.SetStatus(codes.Ok, "Token issued successfully")
    return token, nil
}
```

#### 8.3.2 关键 Span 定义

```
IssueToken (根 Span)
├── VerifyRefreshToken
│   ├── CheckBlacklist (Redis)
│   ├── VerifySignature (Vault)
│   └── ValidateClaims
├── CheckRateLimit (Redis)
├── GenerateAccessToken
│   ├── GetTenantPrivateKey (Vault)
│   ├── SignJWT
│   └── StoreTokenMetadata (PostgreSQL)
└── RevokeOldRefreshToken (Redis + PostgreSQL)
```

---

## 9. 安全加固策略

### 9.1 网络安全

#### 9.1.1 TLS 配置

```go
import "crypto/tls"

func NewTLSConfig() *tls.Config {
    return &tls.Config{
        MinVersion:               tls.VersionTLS13,
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
        CurvePreferences: []tls.CurveID{
            tls.CurveP521,
            tls.CurveP384,
            tls.CurveP256,
        },
    }
}
```

#### 9.1.2 网络隔离

```mermaid
graph TB
    INTERNET[互联网] --> WAF[Web Application Firewall]
    WAF --> LB[负载均衡器]
    
    subgraph DMZ[DMZ 区域]
        LB --> API_GW[API 网关]
    end
    
    subgraph INTERNAL[内部网络]
        API_GW --> AUTH[认证服务集群]
        AUTH --> REDIS[Redis 集群]
        AUTH --> PG[PostgreSQL]
    end
    
    subgraph SECURE[安全区域]
        AUTH -.->|单向访问| VAULT[Vault 集群]
    end
    
    style SECURE fill:#ffe6e6
```

**防火墙规则**：

| 源      | 目标         | 端口   | 协议    | 说明            |
| :----- | :--------- | :--- | :---- | :------------ |
| 互联网    | WAF        | 443  | HTTPS | 外部访问入口        |
| API 网关 | 认证服务       | 8080 | HTTP  | 内网通信（通过 mTLS） |
| 认证服务   | Redis      | 6379 | TCP   | Redis 协议      |
| 认证服务   | PostgreSQL | 5432 | TCP   | PostgreSQL 协议 |
| 认证服务   | Vault      | 8200 | HTTPS | Vault API     |

### 9.2 访问控制

#### 9.2.1 基于角色的访问控制（RBAC）

**角色定义**：

```yaml
roles:
  - name: agent
    permissions:
      - auth:token:issue
      - auth:token:refresh
  
  - name: mgr
    permissions:
      - auth:device:register
      - auth:device:list
  
  - name: admin
    permissions:
      - auth:token:revoke
      - auth:config:update
      - auth:audit:view
```

#### 9.2.2 IP 白名单

```go
func validateIPWhitelist(clientIP string, tenantID string) error {
    whitelist, err := getWhitelist(tenantID)
    if err != nil {
        return err
    }
    
    for _, allowedIP := range whitelist {
        if matchesIP(clientIP, allowedIP) {
            return nil
        }
    }
    
    return ErrIPNotAllowed
}
```

### 9.3 数据加密

#### 9.3.1 敏感数据加密策略

| 数据类型      | 加密方式        | 密钥管理                 |
| :-------- | :---------- | :------------------- |
| 私钥（Vault） | AES-256-GCM | Vault 自动密封密钥         |
| 数据库连接字符串  | 环境变量加密      | Vault Transit Engine |
| 审计日志（PII） | 字段级加密       | 租户数据加密密钥（DEK）        |

#### 9.3.2 传输层加密

**强制 HTTPS 中间件**：

```go
func EnforceHTTPS() gin.HandlerFunc {
    return func(c *gin.Context) {
        if c.Request.Header.Get("X-Forwarded-Proto") != "https" {
            c.JSON(http.StatusUpgradeRequired, gin.H{
                "error": "https_required",
                "message": "This endpoint requires HTTPS",
            })
            c.Abort()
            return
        }
        c.Next()
    }
}
```

### 9.4 安全审计

#### 9.4.1 审计事件清单

| 事件类型 | 触发条件          | 记录内容                         |
| :--- | :------------ | :--------------------------- |
| 设备注册 | 每次注册请求        | MGR ID、Agent ID、IP、时间戳、结果    |
| 令牌颁发 | 每次颁发成功        | Agent ID、Token JTI、Scope、时间戳 |
| 令牌吊销 | 每次吊销操作        | 操作员ID、Token JTI、原因、时间戳       |
| 认证失败 | 失败次数 > 5 次/分钟 | Agent ID、失败原因、IP、时间戳         |
| 密钥轮换 | 每次轮换          | 租户ID、旧密钥ID、新密钥ID、时间戳         |

#### 9.4.2 合规性要求

根据 **SOC 2 Type II**、**ISO 27001** 等标准：

* 审计日志保留期：≥1 年
* 日志完整性保护：使用 HMAC 签名
* 日志访问控制：仅授权管理员可查看
* 日志不可篡改：写入后不可修改或删除

---

## 10. 部署架构

### 10.1 Kubernetes 部署清单

#### 10.1.1 Deployment 配置

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: cbc-platform
spec:
  replicas: 10
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
        version: v1.2.0
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: app
                    operator: In
                    values:
                      - auth-service
              topologyKey: kubernetes.io/hostname
      containers:
        - name: auth-service
          image: cbc/auth-service:v1.2.0
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9090
              name: metrics
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: auth-service-secrets
                  key: database-url
            - name: REDIS_CLUSTER_ADDRS
              value: "redis-cluster-0:6379,redis-cluster-1:6379,redis-cluster-2:6379"
            - name: VAULT_ADDR
              value: "https://vault.cbc-platform.svc.cluster.local:8200"
            - name: VAULT_TOKEN
              valueFrom:
                secretKeyRef:
                  name: auth-service-secrets
                  key: vault-token
          resources:
            requests:
              memory: "512Mi"
              cpu: "500m"
            limits:
              memory: "1Gi"
              cpu: "1000m"
          livenessProbe:
            httpGet:
              path: /health/live
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
```

#### 10.1.2 Service 配置

```yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: cbc-platform
spec:
  selector:
    app: auth-service
  ports:
    - name: http
      port: 80
      targetPort: 8080
    - name: metrics
      port: 9090
      targetPort: 9090
  type: ClusterIP
```

#### 10.1.3 HorizontalPodAutoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
  namespace: cbc-platform
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  minReplicas: 10
  maxReplicas: 100
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Pods
      pods:
        metric:
          name: auth_request_rate
        target:
          type: AverageValue
          averageValue: "10000" # 每个 Pod 处理 10k QPS
```

### 10.2 高可用配置

#### 10.2.1 多可用区部署

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  template:
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: topology.kubernetes.io/zone
                    operator: In
                    values:
                      - us-east-1a
                      - us-east-1b
                      - us-east-1c
```

#### 10.2.2 服务网格配置（Istio）

```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: auth-service
spec:
  hosts:
    - auth-service.cbc-platform.svc.cluster.local
  http:
    - match:
        - uri:
            prefix: /api/v1/auth
      route:
        - destination:
            host: auth-service
            subset: v1
          weight: 90
        - destination:
            host: auth-service
            subset: v2-canary
          weight: 10
      timeout: 5s
      retries:
        attempts: 3
        perTryTimeout: 2s
        retryOn: 5xx,reset,connect-failure
```

---

## 11. 灾难恢复与业务连续性

### 11.1 备份策略

#### 11.1.1 数据库备份

| 备份类型        | 频率           | 保留期  | 存储位置          |
| :---------- | :----------- | :--- | :------------ |
| 全量备份        | 每日 00:00 UTC | 30 天 | AWS S3（跨区域复制） |
| 增量备份        | 每小时          | 7 天  | AWS S3        |
| PITR（时间点恢复） | 实时 WAL 归档    | 7 天  | AWS S3        |

**备份脚本示例**：

```bash
#!/bin/bash
# PostgreSQL 全量备份
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
pg_dump -h $DB_HOST -U $DB_USER -F c -b -v 
  -f /backups/cbc_auth_${BACKUP_DATE}.dump cbc_auth_db

# 上传到 S3
aws s3 cp /backups/cbc_auth_${BACKUP_DATE}.dump 
  s3://cbc-backups/postgres/full/ 
  --storage-class INTELLIGENT_TIERING
```

#### 11.1.2 Vault 备份

```bash
# Vault Snapshot（需要 root token）
vault operator raft snapshot save backup_$(date +%Y%m%d).snap

# 加密备份文件
gpg --encrypt --recipient backup@cloudbrain.cert 
  backup_$(date +%Y%m%d).snap

# 上传到 S3
aws s3 cp backup_$(date +%Y%m%d).snap.gpg 
  s3://cbc-backups/vault/
```

### 11.2 故障恢复流程

#### 11.2.1 RTO/RPO 目标

| 场景    | RTO（恢复时间目标）  | RPO（数据丢失目标） |
| :---- | :----------- | :---------- |
| 单实例故障 | < 1 分钟（自动切换） | 0（无数据丢失）    |
| 可用区故障 | < 5 分钟       | < 1 分钟      |
| 区域性故障 | < 30 分钟      | < 5 分钟      |
| 灾难性故障 | < 4 小时       | < 1 小时      |

#### 11.2.2 故障场景应对

**场景 1：Redis 集群部分节点故障**

```mermaid
sequenceDiagram
    participant MON as 监控系统
    participant OPS as 运维团队
    participant REDIS as Redis 集群
    participant APP as 认证服务
    
    MON->>MON: 检测到 Master-1 宕机
    MON->>OPS: 发送告警（PagerDuty）
    REDIS->>REDIS: 自动故障转移（Slave-1 提升为 Master）
    APP->>REDIS: 请求自动路由到新 Master
    Note over APP,REDIS: 服务无中断（< 5s）
    OPS->>REDIS: 替换故障节点
    REDIS->>REDIS: 重新同步数据
```

**恢复步骤**：

1. **自动阶段（0-30秒）**：

   * Redis Sentinel 检测到 Master 故障
   * 自动将对应 Slave 提升为新 Master
   * 客户端通过 Sentinel 获取新拓扑
2. **人工介入（30分钟内）**：

   * 运维团队调查故障根因
   * 部署新的 Redis 实例替换故障节点
   * 配置为新 Master 的 Slave

**场景 2：PostgreSQL 主库故障**

```bash
# 使用 Patroni 自动故障转移
# 1. Patroni 检测到主库故障
# 2. 自动从 Standby 中选举新主库
# 3. 更新 HAProxy/PgBouncer 路由

# 手动触发故障转移（如需要）
patronictl failover cbc-pg-cluster --candidate pg-standby-1
```

**场景 3：Vault 集群故障**

```bash
# Vault 采用 Raft 协议，自动故障转移
# 如果所有节点都故障，需要手动恢复

# 1. 从备份恢复 Snapshot
vault operator raft snapshot restore backup_20241023.snap

# 2. 解封 Vault（需要 3/5 Unseal Keys）
vault operator unseal <key-1>
vault operator unseal <key-2>
vault operator unseal <key-3>

# 3. 验证服务状态
vault status
```

### 11.3 容量规划与扩展

#### 11.3.1 容量预测模型

**基于历史数据的增长预测**：

```python
# 月度活跃设备增长模型
import numpy as np
from sklearn.linear_model import LinearRegression

# 历史数据（月份，活跃设备数）
X = np.array([[1], [2], [3], [4], [5], [6]])
y = np.array([1000000, 1500000, 2000000, 2800000, 3500000, 4500000])

# 训练模型
model = LinearRegression()
model.fit(X, y)

# 预测未来 6 个月
future_months = np.array([[7], [8], [9], [10], [11], [12]])
predictions = model.predict(future_months)

# 计算所需资源
def calculate_resources(active_devices):
    """
    假设：
    - 每设备每天 50 次 Token 刷新
    - 高峰期 QPS 为均值的 3 倍
    """
    avg_qps = (active_devices * 50) / (24 * 3600)
    peak_qps = avg_qps * 3
    required_pods = int(np.ceil(peak_qps / 10000))  # 每 Pod 10k QPS
    return {
        "peak_qps": peak_qps,
        "required_pods": required_pods,
        "redis_memory_gb": active_devices * 0.001  # 每设备 1KB 缓存
    }
```

#### 11.3.2 扩缩容策略

**自动扩容触发条件**：

```yaml
# Kubernetes HPA 配置
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  minReplicas: 10
  maxReplicas: 100
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
    - type: Pods
      pods:
        metric:
          name: http_requests_per_second
        target:
          type: AverageValue
          averageValue: "8000"  # 留 20% buffer
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 50
          periodSeconds: 60
        - type: Pods
          value: 5
          periodSeconds: 60
      selectPolicy: Max
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
```

**手动扩容决策矩阵**：

| 指标             | 当前值        | 阈值      | 扩容操作            |
| :------------- | :--------- | :------ | :-------------- |
| CPU 使用率        | 85%        | > 80%   | 增加 20% Pod      |
| 内存使用率          | 90%        | > 85%   | 增加 Pod + 调整资源限制 |
| P95 延迟         | 800ms      | > 500ms | 增加 Pod + 检查慢查询  |
| Redis 连接数      | 9000/10000 | > 90%   | 扩展 Redis 集群     |
| PostgreSQL 连接数 | 450/500    | > 90%   | 增加连接池 + 读写分离    |

#### 11.3.3 成本优化建议

**资源使用优化**：

```go
// 1. 连接池复用
var (
    pgPool    *pgxpool.Pool
    redisPool *redis.ClusterClient
)

func init() {
    // PostgreSQL 连接池
    pgPool = NewPgPool(os.Getenv("DATABASE_URL"))
    
    // Redis 连接池
    redisPool = NewRedisCluster()
}

// 2. 缓存预热
func WarmupCache() error {
    // 在服务启动时预加载热点数据
    tenants, err := GetAllActiveTenants()
    if err != nil {
        return err
    }
    
    for _, tenant := range tenants {
        // 缓存租户公钥
        publicKey, _ := vault.GetPublicKey(tenant.ID)
        redis.Set(ctx, fmt.Sprintf("pubkey:%s", tenant.ID), publicKey, 4*time.Hour)
    }
    return nil
}

// 3. 批量操作
func RevokeTokensBatch(jtis []string) error {
    pipe := redisPool.Pipeline()
    for _, jti := range jtis {
        pipe.Set(ctx, fmt.Sprintf("revoked:%s", jti), "1", 24*time.Hour)
    }
    _, err := pipe.Exec(ctx)
    return err
}
```

**基础设施成本优化**：

| 优化项                    | 当前成本          | 优化后成本        | 节省      |
| :--------------------- | :------------ | :----------- | :------ |
| 使用 Spot 实例（非生产）        | $5000/月      | $1500/月     | 70%     |
| Redis 按需扩容（非高峰期）       | $3000/月      | $2000/月     | 33%     |
| S3 存储分层（归档日志）          | $1000/月      | $300/月      | 70%     |
| RDS Reserved Instances | $8000/月      | $5000/月     | 37.5%   |
| **总计**                 | **$17000/月** | **$8800/月** | **48%** |

---

## 12. 运维手册

### 12.1 日常运维任务

#### 12.1.1 健康检查清单

**每日检查项**：

```bash
#!/bin/bash
# 每日健康检查脚本

echo "=== CBC Auth Service Health Check ==="
echo "Date: $(date)"

# 1. 检查服务状态
echo -e "n[1/6] Checking service status..."
kubectl get pods -n cbc-platform -l app=auth-service | grep -v Running && 
  echo "⚠ Warning: Some pods are not running" || echo "✓ All pods running"

# 2. 检查请求成功率
echo -e "n[2/6] Checking request success rate (last 1h)..."
SUCCESS_RATE=$(curl -s "http://prometheus:9090/api/v1/query?query=
  sum(rate(auth_token_issue_success_total[1h]))/
  sum(rate(auth_token_issue_requests_total[1h]))*100" | 
  jq -r '.data.result[0].value[1]')
echo "Success rate: ${SUCCESS_RATE}%"
[[ $(echo "$SUCCESS_RATE < 99.5" | bc) -eq 1 ]] && 
  echo "⚠ Warning: Success rate below 99.5%"

# 3. 检查 P95 延迟
echo -e "n[3/6] Checking P95 latency..."
P95_LATENCY=$(curl -s "http://prometheus:9090/api/v1/query?query=
  histogram_quantile(0.95,rate(auth_token_issue_latency_seconds_bucket[5m]))" | 
  jq -r '.data.result[0].value[1]')
echo "P95 latency: ${P95_LATENCY}s"
[[ $(echo "$P95_LATENCY > 0.5" | bc) -eq 1 ]] && 
  echo "⚠ Warning: P95 latency > 500ms"

# 4. 检查 Redis 集群状态
echo -e "n[4/6] Checking Redis cluster..."
redis-cli --cluster check redis-cluster-0:6379 | 
  grep -q "All 16384 slots covered" && 
  echo "✓ Redis cluster healthy" || 
  echo "⚠ Warning: Redis cluster has issues"

# 5. 检查数据库连接
echo -e "n[5/6] Checking PostgreSQL..."
psql -h $PG_HOST -U $PG_USER -c "SELECT 1" > /dev/null 2>&1 && 
  echo "✓ PostgreSQL connected" || 
  echo "✗ Error: Cannot connect to PostgreSQL"

# 6. 检查 Vault 状态
echo -e "n[6/6] Checking Vault..."
vault status | grep -q "Sealed.*false" && 
  echo "✓ Vault unsealed" || 
  echo "⚠ Warning: Vault is sealed"

echo -e "n=== Health Check Complete ==="
```

#### 12.1.2 常见问题排查

**问题 1：认证失败率突增**

```bash
# 排查步骤
# 1. 查看错误分布
kubectl logs -n cbc-platform -l app=auth-service --tail=1000 | 
  grep "ERROR" | awk '{print $NF}' | sort | uniq -c | sort -rn

# 2. 检查是否为特定租户问题
curl "http://prometheus:9090/api/v1/query?query=
  sum by (tenant_id) (rate(auth_register_failure_total[5m]))"

# 3. 查看 Vault 延迟
curl "http://prometheus:9090/api/v1/query?query=
  histogram_quantile(0.95,rate(vault_api_latency_seconds_bucket[5m]))"

# 4. 检查网络连接
for pod in $(kubectl get pods -n cbc-platform -l app=auth-service -o name); do
  kubectl exec -n cbc-platform $pod -- nc -zv vault.cbc-platform.svc.cluster.local 8200
done
```

**问题 2：内存使用持续增长（可能的内存泄漏）**

```bash
# 1. 采集 Go 内存分析
kubectl exec -n cbc-platform auth-service-pod-001 -- 
  curl http://localhost:8080/debug/pprof/heap > heap.prof

# 2. 使用 pprof 分析
go tool pprof -http=:8081 heap.prof

# 3. 查看 Goroutine 泄漏
kubectl exec -n cbc-platform auth-service-pod-001 -- 
  curl http://localhost:8080/debug/pprof/goroutine?debug=2

# 4. 临时缓解措施（重启高内存 Pod）
kubectl delete pod -n cbc-platform 
  $(kubectl get pods -n cbc-platform -l app=auth-service 
    --sort-by=.status.containerStatuses[0].resourceUsage.memory -o name | tail -1)
```

**问题 3：Redis 连接池耗尽**

```bash
# 1. 检查当前连接数
redis-cli -h redis-cluster-0 -p 6379 INFO clients | grep connected_clients

# 2. 查看慢查询
redis-cli -h redis-cluster-0 -p 6379 SLOWLOG GET 10

# 3. 识别连接泄漏的服务实例
for pod in $(kubectl get pods -n cbc-platform -l app=auth-service -o name); do
  echo "=== $pod ==="
  kubectl exec -n cbc-platform $pod -- netstat -an | grep 6379 | wc -l
done

# 4. 临时扩展连接池（需要重启服务）
kubectl set env deployment/auth-service -n cbc-platform REDIS_POOL_SIZE=200
```

### 12.2 密钥管理操作

#### 12.2.1 密钥轮换流程

```bash
#!/bin/bash
# 租户密钥轮换脚本

TENANT_ID=$1
NEW_KEY_ID="tenant-key-$(date +%Y%m%d-%H%M%S)"

echo "Starting key rotation for tenant: $TENANT_ID"

# 1. 生成新密钥对
openssl genrsa -out ${NEW_KEY_ID}-private.pem 4096
openssl rsa -in ${NEW_KEY_ID}-private.pem -pubout -out ${NEW_KEY_ID}-public.pem

# 2. 存储到 Vault
vault kv put secret/cbc/tenants/${TENANT_ID}/keys/${NEW_KEY_ID} 
  private_key=@${NEW_KEY_ID}-private.pem 
  public_key=@${NEW_KEY_ID}-public.pem 
  created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ) 
  status=active

# 3. 更新数据库配置
psql -h $PG_HOST -U $PG_USER -d cbc_auth_db <<EOF
UPDATE tenant_configs
SET key_rotation_policy = jsonb_set(
  key_rotation_policy,
  '{active_key_id}',
  '"${NEW_KEY_ID}"'
)
WHERE tenant_id = '${TENANT_ID}';
EOF

# 4. 将旧密钥标记为 deprecated（保留用于验证旧令牌）
OLD_KEY_ID=$(psql -h $PG_HOST -U $PG_USER -d cbc_auth_db -t -c 
  "SELECT key_rotation_policy->>'active_key_id' FROM tenant_configs WHERE tenant_id='${TENANT_ID}'")

vault kv patch secret/cbc/tenants/${TENANT_ID}/keys/${OLD_KEY_ID} 
  status=deprecated 
  deprecated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# 5. 清除缓存
redis-cli DEL "pubkey:${TENANT_ID}"

# 6. 验证新密钥可用
curl -X POST http://auth-service/api/v1/auth/token 
  -H "Content-Type: application/json" 
  -d '{
    "grant_type": "refresh_token",
    "refresh_token": "test-refresh-token",
    "tenant_id": "'${TENANT_ID}'"
  }'

echo "Key rotation completed successfully"
echo "New key ID: ${NEW_KEY_ID}"
echo "Old key marked as deprecated: ${OLD_KEY_ID}"

# 清理本地密钥文件
rm -f ${NEW_KEY_ID}-*.pem
```

#### 12.2.2 紧急密钥吊销

```bash
#!/bin/bash
# 紧急密钥吊销（疑似密钥泄露）

TENANT_ID=$1
REASON="emergency_revocation"

echo "⚠️  EMERGENCY: Revoking all keys for tenant $TENANT_ID"
echo "Reason: $REASON"
read -p "Are you sure? (type 'YES' to confirm): " CONFIRM

if [ "$CONFIRM" != "YES" ]; then
  echo "Aborted."
  exit 1
fi

# 1. 立即吊销所有活跃的 Refresh Token
psql -h $PG_HOST -U $PG_USER -d cbc_auth_db <<EOF
UPDATE token_metadata
SET revoked_at = NOW()
WHERE tenant_id = '${TENANT_ID}'
  AND token_type = 'refresh_token'
  AND revoked_at IS NULL
  AND expires_at > NOW();
EOF

# 2. 将黑名单同步到 Redis
JTIS=$(psql -h $PG_HOST -U $PG_USER -d cbc_auth_db -t -c 
  "SELECT jti FROM token_metadata WHERE tenant_id='${TENANT_ID}' AND revoked_at IS NOT NULL")

for JTI in $JTIS; do
  redis-cli SET "revoked:${JTI}" "1" EX 86400
done

# 3. 标记所有密钥为 revoked
vault kv list secret/cbc/tenants/${TENANT_ID}/keys | while read KEY_ID; do
  vault kv patch secret/cbc/tenants/${TENANT_ID}/keys/${KEY_ID} 
    status=revoked 
    revoked_at=$(date -u +%Y-%m-%dT%H:%M:%SZ) 
    revoked_reason="${REASON}"
done

# 4. 强制所有设备重新注册
echo "All refresh tokens revoked. Devices must re-register."
echo "Total tokens revoked: $(echo "$JTIS" | wc -l)"

# 5. 记录审计日志
psql -h $PG_HOST -U $PG_USER -d cbc_auth_db <<EOF
INSERT INTO audit_logs (event_type, tenant_id, result, metadata)
VALUES (
  'emergency_key_revocation',
  '${TENANT_ID}',
  'success',
  '{"reason": "${REASON}", "operator": "'$(whoami)'", "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}'
);
EOF

echo "✓ Emergency revocation completed"
```

### 12.3 性能调优指南

#### 12.3.1 数据库优化

```sql
-- 1. 添加复合索引优化查询
CREATE INDEX CONCURRENTLY idx_token_metadata_tenant_expires 
ON token_metadata (tenant_id, expires_at) 
WHERE revoked_at IS NULL;

-- 2. 分区大表（按月分区）
CREATE TABLE token_metadata_202410 PARTITION OF token_metadata
FOR VALUES FROM ('2024-10-01') TO ('2024-11-01');

-- 3. 定期清理过期数据
DELETE FROM token_metadata
WHERE expires_at < NOW() - INTERVAL '30 days';

VACUUM ANALYZE token_metadata;

-- 4. 优化慢查询
EXPLAIN (ANALYZE, BUFFERS) 
SELECT * FROM token_metadata 
WHERE tenant_id = 'tenant-12345' 
  AND expires_at > NOW() 
  AND revoked_at IS NULL;
```

#### 12.3.2 Redis 优化

```bash
# 1. 监控内存碎片
redis-cli INFO memory | grep mem_fragmentation_ratio
# 如果 > 1.5，执行碎片整理
redis-cli MEMORY PURGE

# 2. 配置最大内存策略
redis-cli CONFIG SET maxmemory 8gb
redis-cli CONFIG SET maxmemory-policy allkeys-lru

# 3. 启用持久化（如需要）
redis-cli CONFIG SET save "900 1 300 10 60 10000"

# 4. 优化慢查询阈值
redis-cli CONFIG SET slowlog-log-slower-than 10000  # 10ms
redis-cli SLOWLOG GET 10
```

#### 12.3.3 应用层优化

```go
// 1. 使用对象池减少 GC 压力
var tokenPool = sync.Pool{
    New: func() interface{} {
        return &TokenResponse{}
    },
}

func IssueToken(req TokenRequest) (*TokenResponse, error) {
    token := tokenPool.Get().(*TokenResponse)
    defer tokenPool.Put(token)
    
    // 业务逻辑...
    return token, nil
}

// 2. 批量预取缓存
func PreloadPublicKeys(tenantIDs []string) error {
    pipe := redisClient.Pipeline()
    for _, tid := range tenantIDs {
        pipe.Get(ctx, fmt.Sprintf("pubkey:%s", tid))
    }
    results, err := pipe.Exec(ctx)
    
    // 缓存未命中的从 Vault 加载
    var missingTenants []string
    for i, result := range results {
        if result.Err() == redis.Nil {
            missingTenants = append(missingTenants, tenantIDs[i])
        }
    }
    
    if len(missingTenants) > 0 {
        return loadPublicKeysFromVault(missingTenants)
    }
    return err
}

// 3. 使用 Context 超时控制
func IssueTokenWithTimeout(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
    ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    
    resultChan := make(chan *TokenResponse, 1)
    errChan := make(chan error, 1)
    
    go func() {
        token, err := issueToken(ctx, req)
        if err != nil {
            errChan <- err
            return
        }
        resultChan <- token
    }()
    
    select {
    case token := <-resultChan:
        return token, nil
    case err := <-errChan:
        return nil, err
    case <-ctx.Done():
        return nil, fmt.Errorf("request timeout: %w", ctx.Err())
    }
}
```

---

## 13. 总结与展望

### 13.1 架构优势

本认证系统架构具备以下核心优势：

1. **高性能**：支持 100 万 QPS，P99 延迟 < 100ms
2. **高可用**：99.99% SLA，多可用区容灾
3. **安全性**：多层级限流、密钥隔离、审计追踪
4. **可扩展**：水平扩展能力，支持千万级设备
5. **可观测**：完善的监控、日志、追踪体系

### 13.2 技术债务管理

**已知限制与改进计划**：

| 限制项               | 影响       | 改进计划           | 优先级 |
| :---------------- | :------- | :------------- | :-- |
| JWT 签名算法固定为 RS256 | 无法支持其他算法 | 支持 ES256、EdDSA | P2  |
| 单一 Redis 集群       | 跨区域延迟高   | 部署多区域 Redis    | P1  |
| 缺少设备指纹绑定          | 令牌可被盗用   | 实现设备指纹验证       | P0  |
| 审计日志无实时告警         | 异常发现滞后   | 集成 SIEM 系统     | P1  |

### 13.3 未来演进方向

**短期规划**：

* 实现零信任架构（Zero Trust）
* 支持 OAuth 2.1 和 FAPI 2.0 标准
* 集成硬件安全模块（HSM）

**长期愿景**：

* 去中心化身份认证（DID）
* 量子安全加密算法
* AI 驱动的异常检测
