<div align="center">
  <img src="logo.png" alt="cbc Logo" width="200" height="200">
  
  # CBC - CloudBrain Certification
  
  [![Build Status](https://img.shields.io/github/workflow/status/turtacn/cbc/CI)](https://github.com/turtacn/cbc/actions)
  [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
  [![Go Report Card](https://goreportcard.com/badge/github.com/turtacn/cbc)](https://goreportcard.com/report/github.com/turtacn/cbc)
  [![Release](https://img.shields.io/github/v/release/turtacn/cbc)](https://github.com/turtacn/cbc/releases)
  [![codecov](https://codecov.io/gh/turtacn/cbc/branch/main/graph/badge.svg)](https://codecov.io/gh/turtacn/cbc)

  **A Distributed Identity Authentication & Authorization Platform for Billions of Devices**
  
  [简体中文](README-zh.md) | English
</div>

---

## 🚀 Mission Statement

**CBC (CloudBrain-Cert)** is a cutting-edge, high-performance distributed identity authentication and authorization platform designed to serve as the **trust anchor** for billions of terminal devices in public network environments. Built on OAuth 2.0 + JWT standards and Zero Trust Architecture principles, CBC delivers:

- **Million-level concurrent token requests** processing capability
- **Sub-10ms token issuance latency** with horizontal scalability
- **Multi-tenant isolation** with independent cryptographic key management
- **Real-time token revocation** with distributed blacklist synchronization
- **Comprehensive observability** through metrics, logs, and distributed tracing

---

## 💡 Why CBC?

### Core Pain Points Addressed

| Pain Point | Traditional Solutions | CBC Solution |
|------------|----------------------|--------------|
| **Scalability Bottleneck** | Stateful session management struggles with millions of concurrent devices | Stateless JWT + Redis cluster + horizontal pod autoscaling supports billions of devices |
| **Security vs Performance Trade-off** | Long-lived tokens (security risk) or frequent authentication (performance penalty) | Dual-token model: Long-lived Refresh Token (365 days) + Short-lived Access Token (15 mins) with local verification |
| **Complex Multi-Tenant Management** | Shared keys across tenants create cross-contamination risks | Per-tenant cryptographic isolation via HashiCorp Vault with automated rotation |
| **Delayed Revocation** | Traditional blacklists suffer from synchronization lag | Redis-based distributed blacklist + JTI indexing for real-time revocation |
| **Vendor Lock-in** | Proprietary solutions with opaque internals | Open-source, standard OAuth 2.0/JWT, cloud-agnostic design |

### Core Value Proposition

1. **Extreme Concurrency**: Process **1M+ token requests/second** with linear scalability
2. **Global Scale**: Support **100M+ device agents** with geo-distributed deployment
3. **Zero Trust Native**: Context-aware access control with device fingerprinting
4. **Developer-Friendly**: Clean REST APIs, comprehensive SDKs, detailed documentation
5. **Production-Ready**: Battle-tested components (PostgreSQL, Redis, Vault, Kafka)

---

## ✨ Key Features

### Core Authentication & Authorization

- ✅ **OAuth 2.0 Compliant**: Standard `refresh_token` grant flow
- ✅ **JWT-Based Access Control**: Self-contained, locally verifiable tokens
- ✅ **Asymmetric Cryptography**: RSA-4096 signatures with per-tenant key pairs
- ✅ **Device Registration Proxy**: Secure initial credential provisioning via MGR
- ✅ **Fine-Grained Permissions**: Scope-based authorization with PEP/PDP separation

### Advanced Security

- 🔒 **One-Time Refresh Tokens**: Automatic rotation upon each use
- 🔒 **mTLS Mutual Authentication**: For MGR-to-CBC communication
- 🔒 **Device Fingerprinting**: Hardware-bound trust roots (TPM/TEE support)
- 🔒 **Context-Aware Access**: Location, time, device health-based policy enforcement
- 🔒 **Comprehensive Audit Trail**: Immutable logs with JTI-TraceID correlation

### High Performance

- ⚡ **Sub-10ms Token Issuance**: Multi-tier caching (L1 in-process + L2 Redis)
- ⚡ **Horizontal Scalability**: Kubernetes-native with HPA/VPA support
- ⚡ **Global Edge Deployment**: GeoDNS + regional clusters for low latency
- ⚡ **Optimized Data Access**: Connection pooling, read replicas, query optimization

### Enterprise-Grade Reliability

- 🛡️ **99.99% Uptime SLA**: Multi-region active-active deployment
- 🛡️ **Graceful Degradation**: Circuit breakers, retry mechanisms, fallback strategies
- 🛡️ **Disaster Recovery**: Cross-region key/blacklist synchronization
- 🛡️ **Rate Limiting**: Global/tenant/device-level QPS protection

### Observability

- 📊 **Prometheus Metrics**: Token issuance rate, latency percentiles, error rates
- 📊 **Distributed Tracing**: Jaeger integration for end-to-end request tracking
- 📊 **Centralized Logging**: Loki aggregation with structured JSON logs
- 📊 **Grafana Dashboards**: Pre-built visualizations for key SLIs/SLOs

---

## 🏗️ Architecture Overview

CBC adopts a **layered microservices architecture** with clear separation of concerns:

```mermaid
graph TB
    subgraph External[External Layer]
        Agent[Device Agent]
        MGR[Intranet MGR]
        IS[Intelligence Service]
    end
    
    subgraph CBC[CBC Cluster]
        LB[Load Balancer]
        API1[API Pod 1]
        API2[API Pod N]
        
        subgraph Services[Business Logic Layer]
            AuthSvc[Auth Service]
            TokenSvc[Token Service]
            PolicySvc[Policy Service]
            RevokeSvc[Revocation Service]
        end
    end
    
    subgraph Data[Data Layer]
        Redis[(Redis Cluster)]
        PG[(PostgreSQL HA)]
        Vault[(Vault KMS)]
        Kafka[(Kafka MQ)]
    end
    
    Agent -->|HTTPS| LB
    MGR -->|mTLS| LB
    IS -->|Fetch Public Key| LB
    
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

👉 **See detailed architecture design**: [docs/architecture.md](docs/architecture.md)
👉 **Full API specifications**: [docs/apis.md](docs/apis.md)

---

## 🚀 Getting Started

### Prerequisites

* Go 1.21+ (for building from source)
* Docker & Docker Compose (for local development)
* Kubernetes 1.25+ (for production deployment)

### Installation

#### Option 1: Install CLI via Go

```bash
go install github.com/turtacn/cbc/cmd/cbc-cli@latest
```

#### Option 2: Download Pre-built Binaries

```bash
# Linux/macOS
curl -sSL https://github.com/turtacn/cbc/releases/latest/download/cbc-linux-amd64 -o cbc-cli
chmod +x cbc-cli
sudo mv cbc-cli /usr/local/bin/

# Verify installation
cbc-cli version
```

#### Option 3: Run with Docker

```bash
docker pull turtacn/cbc:latest
docker run -d -p 8080:8080 --name cbc-server turtacn/cbc:latest
```

### Quick Start Demo

```bash
# 1. Start local development environment (PostgreSQL, Redis, Vault)
docker-compose up -d

# 2. Initialize database schema
cbc-cli db migrate --config configs/dev.yaml

# 3. Start CBC server
cbc-server --config configs/dev.yaml

# 4. Register a new tenant
cbc-cli tenant create 
  --name "MyCompany" 
  --admin-email "admin@example.com"

# Output:
# ✅ Tenant created successfully!
# Tenant ID: tenant-abc123
# Vault Key Path: /cbc/tenants/tenant-abc123/signing-key

# 5. Register MGR credentials for device onboarding
cbc-cli mgr create 
  --tenant-id "tenant-abc123" 
  --mgr-name "IntranetGateway" 
  --output mgr-credentials.json

# Output:
# ✅ MGR created successfully!
# MGR Client ID: mgr-xyz789
# MGR Secret: ***(saved to mgr-credentials.json)

# 6. Simulate device registration (via MGR proxy)
cbc-cli device register 
  --tenant-id "tenant-abc123" 
  --agent-id "device-001" 
  --mgr-client-id "mgr-xyz789" 
  --mgr-secret "$(jq -r .secret mgr-credentials.json)" 
  --output device-refresh-token.txt

# Output:
# ✅ Device registered successfully!
# Refresh Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
# Expires In: 31536000 seconds (365 days)

# 7. Obtain Access Token (simulate roaming agent)
cbc-cli token get 
  --refresh-token "$(cat device-refresh-token.txt)" 
  --scope "intelligence:read intelligence:write"

# Output:
# ✅ Access Token issued successfully!
# Access Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
# Expires In: 900 seconds (15 minutes)
# Scope: intelligence:read intelligence:write

# 8. Verify Access Token locally (simulate Intelligence Service)
cbc-cli token verify 
  --token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." 
  --tenant-id "tenant-abc123"

# Output:
# ✅ Token is valid!
# Subject: device-001
# Tenant: tenant-abc123
# Scope: intelligence:read intelligence:write
# Expires At: 2025-10-23T15:30:00Z
```

### Advanced Usage - Token Revocation

```bash
# Revoke a specific Refresh Token by JTI
cbc-cli token revoke 
  --jti "refresh-jti-12345" 
  --reason "Device reported stolen"

# Output:
# ✅ Token revoked successfully!
# Revoked JTI: refresh-jti-12345
# Blacklist updated in Redis cluster

# Revoke all tokens for a specific device
cbc-cli device revoke 
  --tenant-id "tenant-abc123" 
  --agent-id "device-001" 
  --reason "Security incident"

# Output:
# ✅ All tokens for device-001 revoked!
# Affected Tokens: 3 (1 Refresh Token + 2 Access Tokens still valid)
```

### Performance Testing

```bash
# Run built-in load test
cbc-cli benchmark 
  --target http://localhost:8080 
  --concurrency 1000 
  --duration 60s 
  --scenario token-issuance

# Output:
# 📊 Benchmark Results:
# Total Requests: 1,234,567
# Success Rate: 99.98%
# Avg Latency: 8.3ms
# P95 Latency: 15.2ms
# P99 Latency: 28.7ms
# Throughput: 20,576 req/s
```

---

## 📚 Documentation

* **[Architecture Design](docs/architecture.md)**: Detailed system design and technical decisions
* **[API Reference](docs/apis.md)**: Complete OpenAPI 3.0 specification
* **[Deployment Guide](docs/deployment.md)**: Kubernetes, Docker, cloud provider guides
* **[Security Best Practices](docs/security.md)**: Hardening checklist and compliance
* **[Developer Guide](docs/development.md)**: Contributing workflow and code standards

---

## 🤝 Contributing

We welcome contributions from the community! Whether it's:

* 🐛 Bug reports and fixes
* ✨ New features and enhancements
* 📖 Documentation improvements
* 🌍 Translations

**Please read our [Contributing Guide](CONTRIBUTING.md) before submitting PRs.**

### Development Workflow

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/cbc.git
cd cbc

# 2. Create a feature branch
git checkout -b feature/amazing-feature

# 3. Make your changes and add tests
go test ./...

# 4. Run linters and formatters
make lint
make fmt

# 5. Commit with conventional commits
git commit -m "feat(auth): add device fingerprinting support"

# 6. Push and create a Pull Request
git push origin feature/amazing-feature
```

---

## 📄 License

CBC is licensed under the **Apache License 2.0**.
See [LICENSE](LICENSE) file for details.

```
Copyright 2025 CBC Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## 🙏 Acknowledgments

CBC builds upon the shoulders of giants:

* [OAuth 2.0](https://oauth.net/2/) - Industry-standard authorization framework
* [JWT](https://jwt.io/) - JSON Web Tokens for secure data exchange
* [HashiCorp Vault](https://www.vaultproject.io/) - Secrets and encryption management
* [Kubernetes](https://kubernetes.io/) - Container orchestration platform
* [Go](https://go.dev/) - Efficient, reliable, and simple programming language

---

## 📞 Community & Support

* **GitHub Issues**: [Report bugs or request features](https://github.com/turtacn/cbc/issues)
* **Discussions**: [Ask questions and share ideas](https://github.com/turtacn/cbc/discussions)
* **Slack**: [Join our community workspace](#) *(coming soon)*
* **Email**: [cbc-dev@turtacn.com](mailto:cbc-dev@turtacn.com)

---

<div align="center">
  Made with ❤️ by the CBC Community

⭐ **Star us on GitHub if CBC helps secure your infrastructure!**

</div>