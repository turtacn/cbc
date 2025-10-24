.PHONY: all build test clean docker run help

# 变量定义
APP_NAME=cloudbrain-cert
VERSION=$(shell git describe --tags --always --dirty)
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION=$(shell go version | awk '{print $$3}')
GIT_COMMIT=$(shell git rev-parse HEAD)
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GoVersion=${GO_VERSION} -X main.GitCommit=${GIT_COMMIT}"

# Go 相关变量
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# 构建输出目录
BUILD_DIR=./build
BIN_DIR=./bin

# Docker 相关变量
DOCKER_REGISTRY=your-registry.com
DOCKER_IMAGE=$(DOCKER_REGISTRY)/$(APP_NAME)
DOCKER_TAG=$(VERSION)

all: clean test build ## 执行清理、测试和构建

help: ## 显示帮助信息
	@echo "CloudBrain-Cert Makefile Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## 编译项目
	@echo "Building $(APP_NAME) version $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME) ./cmd/server

build-all: ## 编译所有平台版本
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 ./cmd/server
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 ./cmd/server
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe ./cmd/server

test: ## 运行测试
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.txt -covermode=atomic ./...

test-coverage: test ## 生成测试覆盖率报告
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-integration: ## 运行集成测试
	@echo "Running integration tests..."
	$(GOTEST) -v -tags=integration ./test/integration/...

bench: ## 运行性能测试
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

lint: ## 运行代码检查
	@echo "Running linters..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

fmt: ## 格式化代码
	@echo "Formatting code..."
	$(GOCMD) fmt ./...
	@which goimports > /dev/null || (echo "Installing goimports..." && go install golang.org/x/tools/cmd/goimports@latest)
	goimports -w .

vet: ## 运行 go vet
	@echo "Running go vet..."
	$(GOCMD) vet ./...

clean: ## 清理编译产物
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BIN_DIR)
	rm -rf $(BUILD_DIR)
	rm -f coverage.txt coverage.html

deps: ## 下载依赖
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

deps-update: ## 更新依赖
	@echo "Updating dependencies..."
	$(GOMOD) tidy
	$(GOGET) -u ./...
	$(GOMOD) tidy

run: build ## 编译并运行
	@echo "Running $(APP_NAME)..."
	$(BIN_DIR)/$(APP_NAME)

run-dev: ## 以开发模式运行
	@echo "Running in development mode..."
	$(GOCMD) run ./cmd/server --config=./config/dev.yaml

docker-build: ## 构建 Docker 镜像
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -t $(DOCKER_IMAGE):latest .

docker-push: docker-build ## 推送 Docker 镜像
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest

docker-run: ## 运行 Docker 容器
	@echo "Running Docker container..."
	docker run -d -p 8080:8080 --name $(APP_NAME) $(DOCKER_IMAGE):latest

docker-stop: ## 停止 Docker 容器
	@echo "Stopping Docker container..."
	docker stop $(APP_NAME)
	docker rm $(APP_NAME)

docker-compose-up: ## 使用 docker-compose 启动服务
	@echo "Starting services with docker-compose..."
	docker-compose up -d

docker-compose-down: ## 使用 docker-compose 停止服务
	@echo "Stopping services with docker-compose..."
	docker-compose down

proto: ## 生成 protobuf 代码
	@echo "Generating protobuf code..."
	@which protoc > /dev/null || (echo "Error: protoc not found. Please install Protocol Buffers compiler." && exit 1)
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/*.proto

mock: ## 生成 mock 代码
	@echo "Generating mock code..."
	@which mockgen > /dev/null || (echo "Installing mockgen..." && go install github.com/golang/mock/mockgen@latest)
	go generate ./...

install: build ## 安装二进制文件到 $GOPATH/bin
	@echo "Installing $(APP_NAME)..."
	cp $(BIN_DIR)/$(APP_NAME) $(GOPATH)/bin/

uninstall: ## 卸载二进制文件
	@echo "Uninstalling $(APP_NAME)..."
	rm -f $(GOPATH)/bin/$(APP_NAME)

security-scan: ## 运行安全扫描
	@echo "Running security scan..."
	@which gosec > /dev/null || (echo "Installing gosec..." && go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec ./...

version: ## 显示版本信息
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Go Version: $(GO_VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"

init-db: ## 初始化数据库
	@echo "Initializing database..."
	$(BIN_DIR)/$(APP_NAME) migrate up

migrate-up: ## 执行数据库迁移（升级）
	@echo "Running database migrations (up)..."
	$(BIN_DIR)/$(APP_NAME) migrate up

migrate-down: ## 执行数据库迁移（降级）
	@echo "Running database migrations (down)..."
	$(BIN_DIR)/$(APP_NAME) migrate down

migrate-status: ## 查看数据库迁移状态
	@echo "Database migration status..."
	$(BIN_DIR)/$(APP_NAME) migrate status

k8s-deploy: ## 部署到 Kubernetes
	@echo "Deploying to Kubernetes..."
	kubectl apply -f k8s/

k8s-delete: ## 从 Kubernetes 删除
	@echo "Deleting from Kubernetes..."
	kubectl delete -f k8s/

.DEFAULT_GOAL := help
