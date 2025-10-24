# CBC Auth Service - Kubernetes 部署文档

本文档详细说明了如何在 Kubernetes 集群中部署 CBC 认证服务。

## 目录

- [前置条件](#前置条件)
- [命名空间创建](#命名空间创建)
- [Secret 和 ConfigMap 配置](#secret-和-configmap-配置)
- [部署步骤](#部署步骤)
- [验证部署](#验证部署)
- [升级和回滚策略](#升级和回滚策略)
- [监控和告警配置](#监控和告警配置)
- [故障排查指南](#故障排查指南)

---

## 前置条件

### 1. Kubernetes 集群

- **版本要求**：Kubernetes v1.24+
- **节点配置**：
  - 至少 3 个 Worker 节点
  - 每个节点至少 4 CPU 核心、8GB 内存
  - 支持动态存储卷（StorageClass）

### 2. 工具安装

#### kubectl

```bash
# macOS
brew install kubectl

# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# 验证安装
kubectl version --client
````

#### Helm（可选）

```bash
# macOS
brew install helm

# Linux
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# 验证安装
helm version
```

#### kustomize（可选）

```bash
# macOS
brew install kustomize

# Linux
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash

# 验证安装
kustomize version
```

### 3. 集群访问配置

```bash
# 配置 kubectl 上下文
kubectl config use-context <your-cluster-context>

# 验证集群连接
kubectl cluster-info
kubectl get nodes
```

---

## 命名空间创建

### 创建命名空间

```bash
kubectl create namespace cbc-platform

# 或使用 YAML 文件
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: cbc-platform
  labels:
    name: cbc-platform
    environment: production
EOF
```

### 设置默认命名空间（可选）

```bash
kubectl config set-context --current --namespace=cbc-platform
```

---

## Secret 和 ConfigMap 配置

### 1. 创建数据库连接 Secret

```bash
kubectl create secret generic auth-service-db \
  --from-literal=database-url='postgresql://cbc_user:secure_password@postgres.cbc-platform.svc.cluster.local:5432/cbc_auth_db?sslmode=require' \
  -n cbc-platform
```

### 2. 创建 Redis 连接 Secret

```bash
kubectl create secret generic auth-service-redis \
  --from-literal=redis-password='redis_secure_password' \
  -n cbc-platform
```

### 3. 创建 Vault Token Secret

```bash
kubectl create secret generic auth-service-vault \
  --from-literal=vault-token='s.YourVaultTokenHere' \
  -n cbc-platform
```

### 4. 创建 TLS 证书 Secret

```bash
# 假设已有 TLS 证书文件
kubectl create secret tls auth-service-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n cbc-platform
```

### 5. 创建应用配置 ConfigMap

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-service-config
  namespace: cbc-platform
data:
  APP_ENV: "production"
  LOG_LEVEL: "info"
  SERVER_PORT: "8080"
  METRICS_PORT: "9090"
  REDIS_CLUSTER_ADDRS: "redis-cluster-0:6379,redis-cluster-1:6379,redis-cluster-2:6379"
  VAULT_ADDR: "https://vault.cbc-platform.svc.cluster.local:8200"
  JWT_ALGORITHM: "RS256"
  REFRESH_TOKEN_TTL: "2592000"  # 30 days
  ACCESS_TOKEN_TTL: "900"       # 15 minutes
  RATE_LIMIT_GLOBAL: "1000000"
  RATE_LIMIT_TENANT: "100000"
  RATE_LIMIT_AGENT: "10"
EOF
```

---

## 部署步骤

### 方式一：使用原始 YAML 文件

#### 1. 应用 Deployment

```bash
kubectl apply -f deployments/kubernetes/deployment.yaml
```

#### 2. 应用 Service

```bash
kubectl apply -f deployments/kubernetes/service.yaml
```

#### 3. 应用 HPA（水平自动扩展）

```bash
kubectl apply -f deployments/kubernetes/hpa.yaml
```

#### 4. 应用 Ingress（如果需要外部访问）

```bash
kubectl apply -f deployments/kubernetes/ingress.yaml
```

### 方式二：使用 Kustomize

```bash
# 查看最终生成的 YAML
kubectl kustomize deployments/kubernetes/overlays/production

# 应用配置
kubectl apply -k deployments/kubernetes/overlays/production
```

### 方式三：使用 Helm（如果提供了 Helm Chart）

```bash
# 添加 Helm 仓库（如果有）
helm repo add cbc https://charts.cloudbrain.cert
helm repo update

# 安装
helm install auth-service cbc/auth-service \
  --namespace cbc-platform \
  --values deployments/helm/values-production.yaml

# 或从本地 Chart 安装
helm install auth-service ./deployments/helm/auth-service \
  --namespace cbc-platform \
  --values deployments/helm/values-production.yaml
```

---

## 验证部署

### 1. 检查 Pod 状态

```bash
# 查看所有 Pod
kubectl get pods -n cbc-platform

# 查看特定 Deployment 的 Pod
kubectl get pods -n cbc-platform -l app=auth-service

# 期望输出：
# NAME                             READY   STATUS    RESTARTS   AGE
# auth-service-5d6f8c9b7d-abcde    1/1     Running   0          2m
# auth-service-5d6f8c9b7d-fghij    1/1     Running   0          2m
```

### 2. 查看 Pod 日志

```bash
# 查看单个 Pod 日志
kubectl logs -n cbc-platform auth-service-5d6f8c9b7d-abcde

# 查看所有副本日志（使用 stern 工具）
stern -n cbc-platform auth-service

# 实时跟踪日志
kubectl logs -n cbc-platform -l app=auth-service --tail=100 -f
```

### 3. 检查 Service

```bash
kubectl get svc -n cbc-platform

# 期望输出：
# NAME           TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
# auth-service   ClusterIP   10.96.123.45    <none>        80/TCP     5m
```

### 4. 检查 Endpoints

```bash
kubectl get endpoints -n cbc-platform auth-service

# 期望输出显示所有健康的 Pod IP
```

### 5. 健康检查

```bash
# 使用临时 Pod 进行内部测试
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -n cbc-platform -- \
  curl http://auth-service.cbc-platform.svc.cluster.local/health/live

# 期望输出：
# {"status":"ok","timestamp":"2024-10-24T10:30:00Z"}
```

### 6. 端到端测试

```bash
# 设置端口转发
kubectl port-forward -n cbc-platform svc/auth-service 8080:80

# 在另一个终端测试
curl http://localhost:8080/health/live
curl http://localhost:8080/health/ready
```

---

## 升级和回滚策略

### 1. 升级策略

#### 滚动更新（默认）

```yaml
# deployment.yaml 中的配置
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1    # 最多 1 个 Pod 不可用
      maxSurge: 1          # 最多额外创建 1 个 Pod
```

#### 执行升级

```bash
# 更新镜像版本
kubectl set image deployment/auth-service \
  auth-service=cbc/auth-service:v1.3.0 \
  -n cbc-platform

# 或应用新的 YAML 文件
kubectl apply -f deployments/kubernetes/deployment.yaml

# 查看升级状态
kubectl rollout status deployment/auth-service -n cbc-platform
```

### 2. 金丝雀发布

```bash
# 1. 创建金丝雀 Deployment（10% 流量）
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service-canary
  namespace: cbc-platform
spec:
  replicas: 1
  selector:
    matchLabels:
      app: auth-service
      version: canary
  template:
    metadata:
      labels:
        app: auth-service
        version: canary
    spec:
      containers:
      - name: auth-service
        image: cbc/auth-service:v1.3.0-rc1
        # ... 其他配置同主 Deployment
EOF

# 2. 观察金丝雀版本的指标和日志
kubectl logs -n cbc-platform -l version=canary

# 3. 如果一切正常，逐步增加金丝雀副本数
kubectl scale deployment/auth-service-canary --replicas=3 -n cbc-platform

# 4. 最终完全切换到新版本
kubectl set image deployment/auth-service \
  auth-service=cbc/auth-service:v1.3.0-rc1 \
  -n cbc-platform

# 5. 删除金丝雀 Deployment
kubectl delete deployment auth-service-canary -n cbc-platform
```

### 3. 蓝绿部署

```bash
# 1. 创建绿色环境（新版本）
kubectl apply -f deployments/kubernetes/deployment-green.yaml

# 2. 验证绿色环境健康
kubectl get pods -n cbc-platform -l environment=green

# 3. 切换流量到绿色环境（修改 Service selector）
kubectl patch service auth-service -n cbc-platform -p \
  '{"spec":{"selector":{"environment":"green"}}}'

# 4. 保留蓝色环境一段时间以便回滚
# 如果一切正常，删除蓝色环境
kubectl delete deployment auth-service-blue -n cbc-platform
```

### 4. 回滚操作

```bash
# 查看历史版本
kubectl rollout history deployment/auth-service -n cbc-platform

# 回滚到上一个版本
kubectl rollout undo deployment/auth-service -n cbc-platform

# 回滚到特定版本
kubectl rollout undo deployment/auth-service \
  --to-revision=2 \
  -n cbc-platform

# 查看回滚状态
kubectl rollout status deployment/auth-service -n cbc-platform
```

---

## 监控和告警配置

### 1. Prometheus 集成

#### 安装 Prometheus Operator

```bash
# 使用 Helm 安装 kube-prometheus-stack
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --values - <<EOF
prometheus:
  prometheusSpec:
    serviceMonitorSelectorNilUsesHelmValues: false
    podMonitorSelectorNilUsesHelmValues: false
    retention: 30d
    storageSpec:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 50Gi
grafana:
  adminPassword: "admin_password_change_me"
  ingress:
    enabled: true
    hosts:
      - grafana.cbc-platform.local
EOF
```

#### 创建 ServiceMonitor

```bash
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: auth-service-metrics
  namespace: cbc-platform
  labels:
    app: auth-service
spec:
  selector:
    matchLabels:
      app: auth-service
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
EOF
```

### 2. Grafana 仪表板

#### 导入预定义仪表板

```bash
# 1. 访问 Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80

# 2. 在浏览器中打开 http://localhost:3000
# 3. 导入仪表板（Dashboard ID: 待提供）或使用自定义 JSON
```

#### 自定义仪表板示例

创建文件 `dashboards/auth-service-dashboard.json`（在 `docs/deployment/` 目录中）：

```json
{
  "dashboard": {
    "title": "CBC Auth Service Dashboard",
    "panels": [
      {
        "title": "Request Rate (QPS)",
        "targets": [
          {
            "expr": "sum(rate(auth_token_issue_requests_total[5m]))"
          }
        ]
      },
      {
        "title": "P95 Latency",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(auth_token_issue_latency_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "sum(rate(auth_token_issue_failure_total[5m])) / sum(rate(auth_token_issue_requests_total[5m]))"
          }
        ]
      }
    ]
  }
}
```

### 3. 告警规则

#### 创建 PrometheusRule

```bash
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: auth-service-alerts
  namespace: cbc-platform
  labels:
    prometheus: kube-prometheus
spec:
  groups:
  - name: auth-service
    interval: 30s
    rules:
    - alert: HighErrorRate
      expr: |
        sum(rate(auth_token_issue_failure_total[5m])) 
        / sum(rate(auth_token_issue_requests_total[5m])) 
        > 0.05
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "Auth service error rate > 5%"
        description: "Error rate is {{ $value | humanizePercentage }}"
    
    - alert: HighLatency
      expr: |
        histogram_quantile(0.95, 
          rate(auth_token_issue_latency_seconds_bucket[5m])
        ) > 0.5
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Auth service P95 latency > 500ms"
        description: "P95 latency is {{ $value }}s"
    
    - alert: PodNotReady
      expr: |
        kube_pod_status_ready{namespace="cbc-platform", pod=~"auth-service-.*"}
        == 0
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Auth service pod not ready"
        description: "Pod {{ $labels.pod }} has been not ready for 5 minutes"
EOF
```

### 4. Alertmanager 配置

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: alertmanager-config
  namespace: monitoring
stringData:
  alertmanager.yaml: |
    global:
      resolve_timeout: 5m
    route:
      group_by: ['alertname', 'cluster', 'service']
      group_wait: 10s
      group_interval: 10s
      repeat_interval: 12h
      receiver: 'pagerduty'
      routes:
      - match:
          severity: critical
        receiver: pagerduty
      - match:
          severity: warning
        receiver: slack
    receivers:
    - name: 'pagerduty'
      pagerduty_configs:
      - service_key: '<your-pagerduty-service-key>'
    - name: 'slack'
      slack_configs:
      - api_url: '<your-slack-webhook-url>'
        channel: '#cbc-alerts'
        title: 'CBC Auth Service Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
EOF
```

---

## 故障排查指南

### 1. Pod 无法启动

#### 症状

```bash
kubectl get pods -n cbc-platform
# NAME                             READY   STATUS             RESTARTS   AGE
# auth-service-5d6f8c9b7d-abcde    0/1     CrashLoopBackOff   5          5m
```

#### 排查步骤

```bash
# 1. 查看 Pod 详情
kubectl describe pod auth-service-5d6f8c9b7d-abcde -n cbc-platform

# 2. 查看日志
kubectl logs auth-service-5d6f8c9b7d-abcde -n cbc-platform

# 3. 检查容器启动命令
kubectl get pod auth-service-5d6f8c9b7d-abcde -n cbc-platform -o jsonpath='{.spec.containers[0].command}'

# 4. 检查环境变量
kubectl exec -n cbc-platform auth-service-5d6f8c9b7d-abcde -- env

# 5. 检查存储卷挂载
kubectl get pod auth-service-5d6f8c9b7d-abcde -n cbc-platform -o jsonpath='{.spec.volumes}'
```

#### 常见问题

| 问题               | 原因     | 解决方法                            |
| ---------------- | ------ | ------------------------------- |
| ImagePullBackOff | 镜像拉取失败 | 检查镜像名称、标签、私有仓库凭证                |
| CrashLoopBackOff | 应用启动失败 | 查看日志，检查配置文件、依赖服务                |
| OOMKilled        | 内存不足   | 增加资源限制（resources.limits.memory） |

### 2. 服务无法访问

#### 症状

```bash
curl http://auth-service.cbc-platform.svc.cluster.local/health/live
# curl: (7) Failed to connect to auth-service.cbc-platform.svc.cluster.local port 80: Connection refused
```

#### 排查步骤

```bash
# 1. 检查 Service
kubectl get svc auth-service -n cbc-platform
kubectl describe svc auth-service -n cbc-platform

# 2. 检查 Endpoints
kubectl get endpoints auth-service -n cbc-platform

# 3. 检查 Pod 标签是否匹配 Service Selector
kubectl get pods -n cbc-platform --show-labels
kubectl get svc auth-service -n cbc-platform -o jsonpath='{.spec.selector}'

# 4. 测试 Pod 直接访问
POD_IP=$(kubectl get pod auth-service-5d6f8c9b7d-abcde -n cbc-platform -o jsonpath='{.status.podIP}')
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -n cbc-platform -- \
  curl http://$POD_IP:8080/health/live

# 5. 检查网络策略
kubectl get networkpolicies -n cbc-platform
```

### 3. 数据库连接失败

#### 症状

```bash
kubectl logs -n cbc-platform auth-service-5d6f8c9b7d-abcde | grep -i "database"
# ERROR: failed to connect to database: dial tcp 10.96.1.2:5432: i/o timeout
```

#### 排查步骤

```bash
# 1. 检查数据库 Service 是否存在
kubectl get svc -n cbc-platform | grep postgres

# 2. 测试 DNS 解析
kubectl exec -n cbc-platform auth-service-5d6f8c9b7d-abcde -- \
  nslookup postgres.cbc-platform.svc.cluster.local

# 3. 测试网络连通性
kubectl exec -n cbc-platform auth-service-5d6f8c9b7d-abcde -- \
  nc -zv postgres.cbc-platform.svc.cluster.local 5432

# 4. 检查数据库密码 Secret
kubectl get secret auth-service-db -n cbc-platform -o jsonpath='{.data.database-url}' | base64 -d

# 5. 验证数据库凭证
kubectl run -it --rm psql --image=postgres:15 --restart=Never -n cbc-platform -- \
  psql "postgresql://cbc_user:password@postgres.cbc-platform.svc.cluster.local:5432/cbc_auth_db?sslmode=require"
```

### 4. Redis 连接失败

#### 症状

```bash
kubectl logs -n cbc-platform auth-service-5d6f8c9b7d-abcde | grep -i "redis"
# ERROR: redis connection failed: NOAUTH Authentication required
```

#### 排查步骤

```bash
# 1. 检查 Redis 集群状态
kubectl exec -n cbc-platform redis-cluster-0 -- redis-cli cluster info

# 2. 测试 Redis 连接
kubectl run -it --rm redis-client --image=redis:7-alpine --restart=Never -n cbc-platform -- \
  redis-cli -h redis-cluster-0.cbc-platform.svc.cluster.local -p 6379 -a 'password' PING

# 3. 检查 Redis 密码 Secret
kubectl get secret auth-service-redis -n cbc-platform -o jsonpath='{.data.redis-password}' | base64 -d

# 4. 验证 Redis 集群节点
kubectl exec -n cbc-platform redis-cluster-0 -- \
  redis-cli -a 'password' cluster nodes
```

### 5. 内存泄漏

#### 症状

```bash
kubectl top pods -n cbc-platform
# NAME                             CPU(cores)   MEMORY(bytes)
# auth-service-5d6f8c9b7d-abcde    500m         950Mi  # 持续增长
```

#### 排查步骤

```bash
# 1. 启用 pprof（如果应用支持）
kubectl port-forward -n cbc-platform auth-service-5d6f8c9b7d-abcde 6060:6060

# 2. 采集堆内存快照
curl http://localhost:6060/debug/pprof/heap > heap.prof

# 3. 使用 pprof 分析
go tool pprof -http=:8081 heap.prof

# 4. 查看 Goroutine 泄漏
curl http://localhost:6060/debug/pprof/goroutine?debug=2

# 5. 临时重启高内存 Pod
kubectl delete pod auth-service-5d6f8c9b7d-abcde -n cbc-platform
```

### 6. HPA 不工作

#### 症状

```bash
kubectl get hpa -n cbc-platform
# NAME           REFERENCE                   TARGETS         MINPODS   MAXPODS   REPLICAS   AGE
# auth-service   Deployment/auth-service     <unknown>/70%   10        100       10         5m
```

#### 排查步骤

```bash
# 1. 检查 Metrics Server 是否运行
kubectl get deployment metrics-server -n kube-system

# 2. 检查 Pod 资源指标
kubectl top pods -n cbc-platform -l app=auth-service

# 3. 查看 HPA 详情
kubectl describe hpa auth-service -n cbc-platform

# 4. 检查 Pod 是否设置了资源请求
kubectl get pod auth-service-5d6f8c9b7d-abcde -n cbc-platform \
  -o jsonpath='{.spec.containers[0].resources}'

# 5. 手动测试扩缩容
kubectl scale deployment/auth-service --replicas=15 -n cbc-platform
```

---

## 附录

### A. 完整部署脚本

```bash
#!/bin/bash
# deploy.sh - 一键部署脚本

set -e

NAMESPACE="cbc-platform"
DEPLOYMENT_DIR="deployments/kubernetes"

echo "=== CBC Auth Service Deployment ==="

# 1. 创建命名空间
echo "[1/6] Creating namespace..."
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# 2. 创建 Secrets
echo "[2/6] Creating secrets..."
kubectl apply -f $DEPLOYMENT_DIR/secrets.yaml

# 3. 创建 ConfigMap
echo "[3/6] Creating configmap..."
kubectl apply -f $DEPLOYMENT_DIR/configmap.yaml

# 4. 部署应用
echo "[4/6] Deploying application..."
kubectl apply -f $DEPLOYMENT_DIR/deployment.yaml

# 5. 创建 Service
echo "[5/6] Creating service..."
kubectl apply -f $DEPLOYMENT_DIR/service.yaml

# 6. 创建 HPA
echo "[6/6] Creating HPA..."
kubectl apply -f $DEPLOYMENT_DIR/hpa.yaml

# 等待部署完成
echo "Waiting for deployment to be ready..."
kubectl rollout status deployment/auth-service -n $NAMESPACE

echo "=== Deployment Complete ==="
kubectl get pods -n $NAMESPACE -l app=auth-service
```

### B. 清理脚本

```bash
#!/bin/bash
# cleanup.sh - 清理部署资源

set -e

NAMESPACE="cbc-platform"

echo "=== Cleaning up CBC Auth Service ==="

kubectl delete hpa auth-service -n $NAMESPACE --ignore-not-found=true
kubectl delete service auth-service -n $NAMESPACE --ignore-not-found=true
kubectl delete deployment auth-service -n $NAMESPACE --ignore-not-found=true
kubectl delete configmap auth-service-config -n $NAMESPACE --ignore-not-found=true
kubectl delete secret auth-service-db auth-service-redis auth-service-vault -n $NAMESPACE --ignore-not-found=true

echo "=== Cleanup Complete ==="
```

---

## 参考资料

* [Kubernetes 官方文档](https://kubernetes.io/docs/)
* [Helm 官方文档](https://helm.sh/docs/)
* [Prometheus Operator 文档](https://prometheus-operator.dev/)
* [Istio Service Mesh](https://istio.io/latest/docs/)

---

**文档版本**：v1.0
**最后更新**：2024-10-24
**维护者**：CBC Platform Team

<!--Personal.AI order the ending-->
