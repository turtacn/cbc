//go:build !test

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	// 应用层
	"github.com/turtacn/cbc/internal/application/service"

	// 配置层
	"github.com/turtacn/cbc/internal/config"

	// 领域层
	"github.com/turtacn/cbc/internal/domain/repository"
	domainService "github.com/turtacn/cbc/internal/domain/service"

	// 基础设施层
	"github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	redisInfra "github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/internal/infrastructure/ratelimit"

	// 接口层
	grpcInterface "github.com/turtacn/cbc/internal/interfaces/grpc"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	httpRouter "github.com/turtacn/cbc/internal/interfaces/http/router"

	// 公共包
	"github.com/turtacn/cbc/pkg/logger"
)

const (
	// 服务信息
	ServiceName    = "cbc-auth-service"
	ServiceVersion = "v1.2.0"

	// 默认端口
	DefaultHTTPPort = "8080"
	DefaultGRPCPort = "50051"

	// 优雅关闭超时
	ShutdownTimeout = 30 * time.Second

	// 定时任务间隔
	CleanupInterval = 1 * time.Hour
)

// Application 应用程序结构体
type Application struct {
	// 配置
	config *config.Config

	// 日志
	logger logger.Logger

	// 数据库连接
	dbConn      *postgres.DBConnection
	redisClient *redisInfra.RedisConnection

	// 基础设施组件
	vaultClient  *crypto.VaultClient
	cacheManager *redisInfra.CacheManager
	keyManager   *crypto.KeyManager
	jwtManager   *crypto.JWTManager
	rateLimiter  domainService.RateLimitService

	// 监控组件
	metrics *monitoring.Metrics

	// 仓储实现
	tokenRepo  repository.TokenRepository
	deviceRepo repository.DeviceRepository
	tenantRepo repository.TenantRepository

	// 应用服务
	authAppService   service.AuthAppService
	deviceAppService service.DeviceAppService
	tenantAppService service.TenantAppService

	// HTTP 服务
	httpServer *http.Server
	ginEngine  *gin.Engine

	// gRPC 服务
	grpcServer   *grpc.Server
	grpcListener net.Listener

	// 定时任务
	cleanupTicker *time.Ticker

	// 上下文
	ctx    context.Context
	cancel context.CancelFunc
}

func realMain() {
	// 创建应用实例
	app, err := NewApplication()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize application: %v\n", err)
		os.Exit(1)
	}

	// 启动应用
	if err := app.Start(); err != nil {
		app.logger.Error(context.Background(), "Failed to start application", err)
		os.Exit(1)
	}

	// 等待系统信号
	app.WaitForShutdown()

	// 优雅关闭
	if err := app.Shutdown(); err != nil {
		app.logger.Error(context.Background(), "Failed to shutdown gracefully", err)
		os.Exit(1)
	}

	app.logger.Info(context.Background(), "Application stopped successfully")
}

// NewApplication 创建应用实例
func NewApplication() (*Application, error) {
	ctx, cancel := context.WithCancel(context.Background())

	app := &Application{
		ctx:    ctx,
		cancel: cancel,
	}

	// 1. 加载配置
	if err := app.loadConfig(); err != nil {
		cancel()
		return nil, fmt.Errorf("load config: %w", err)
	}

	// 2. 初始化日志
	if err := app.initLogger(); err != nil {
		cancel()
		return nil, fmt.Errorf("init logger: %w", err)
	}

	app.logger.Info(context.Background(), "Starting CBC Auth Service",
		logger.String("version", ServiceVersion),
	)

	// 3. 初始化数据库连接
	if err := app.initDatabase(); err != nil {
		return nil, fmt.Errorf("init database: %w", err)
	}

	// 4. 初始化 Vault 客户端
	if err := app.initVault(); err != nil {
		return nil, fmt.Errorf("init vault: %w", err)
	}

	// 5. 初始化基础设施组件
	if err := app.initInfrastructure(); err != nil {
		return nil, fmt.Errorf("init infrastructure: %w", err)
	}

	// 6. 初始化监控组件
	if err := app.initMonitoring(); err != nil {
		return nil, fmt.Errorf("init monitoring: %w", err)
	}

	// 7. 初始化仓储实现
	if err := app.initRepositories(); err != nil {
		return nil, fmt.Errorf("init repositories: %w", err)
	}

	// 8. 初始化应用服务
	if err := app.initApplicationServices(); err != nil {
		return nil, fmt.Errorf("init application services: %w", err)
	}

	// 9. 初始化接口层
	if err := app.initInterfaces(); err != nil {
		return nil, fmt.Errorf("init interfaces: %w", err)
	}

	return app, nil
}

// loadConfig 加载配置
func (app *Application) loadConfig() error {
	loader := config.NewLoader()
	cfg, err := loader.Load()
	if err != nil {
		return err
	}

	app.config = cfg
	return nil
}

// initLogger 初始化日志
func (app *Application) initLogger() error {
	// TODO: Implement a logger that reads from the config.
	log := logger.NewDefaultLogger()
	app.logger = log
	return nil
}

// initDatabase 初始化数据库连接
func (app *Application) initDatabase() error {
	// PostgreSQL 连接池
	dbConn, err := postgres.NewDBConnection(
		app.ctx,
		&app.config.Database,
		app.logger,
	)
	if err != nil {
		return fmt.Errorf("create postgres pool: %w", err)
	}
	app.dbConn = dbConn

	// 验证连接
	if err := dbConn.Ping(app.ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}

	app.logger.Info(context.Background(), "PostgreSQL connected",
		logger.String("host", app.config.Database.Host),
	)

	// Redis 集群客户端
	redisConfig := &redisInfra.Config{
		Mode:         redisInfra.ConnectionMode(app.config.Redis.Address),
		ClusterAddrs: app.config.Redis.ClusterAddrs,
		Password:     app.config.Redis.Password,
		DB:           app.config.Redis.DB,
		PoolSize:     app.config.Redis.PoolSize,
		MinIdleConns: app.config.Redis.MinIdleConns,
		MaxRetries:   app.config.Redis.MaxRetries,
		DialTimeout:  app.config.Redis.DialTimeout,
		ReadTimeout:  app.config.Redis.ReadTimeout,
		WriteTimeout: app.config.Redis.WriteTimeout,
	}
	redisClient := redisInfra.NewRedisConnection(
		redisConfig,
		app.logger,
	)
	if err := redisClient.Connect(); err != nil {
		return fmt.Errorf("create redis client: %w", err)
	}
	app.redisClient = redisClient

	// 验证连接
	if err := redisClient.Ping(app.ctx); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}

	app.logger.Info(context.Background(), "Redis cluster connected",
		logger.String("addrs", app.config.Redis.Address),
	)

	return nil
}

// initVault 初始化 Vault 客户端
func (app *Application) initVault() error {
	vaultClient, err := crypto.NewVaultClient(
		&crypto.VaultConfig{
			Address: app.config.Vault.Address,
			Token:   app.config.Vault.Token,
		},
		app.logger,
	)
	if err != nil {
		return fmt.Errorf("create vault client: %w", err)
	}

	app.vaultClient = vaultClient

	// 验证连接
	if _, err := vaultClient.Health(app.ctx); err != nil {
		return fmt.Errorf("ping vault: %w", err)
	}

	app.logger.Info(context.Background(), "Vault connected",
		logger.String("address", app.config.Vault.Address),
	)

	return nil
}

// initInfrastructure 初始化基础设施组件
func (app *Application) initInfrastructure() error {
	// 缓存管理器
	app.cacheManager = redisInfra.NewCacheManager(
		app.redisClient.GetClient(),
		"",
		0,
		app.logger,
	)

	// 密钥管理器
	{
		km, err := crypto.NewKeyManager(app.vaultClient, app.cacheManager, nil, app.logger)
		if err != nil {
			return fmt.Errorf("create key manager: %w", err)
		}
		app.keyManager = km
	}

	// JWT 管理器
	{
		jm, err := crypto.NewJWTManager(app.keyManager, nil, app.logger)
		if err != nil {
			return fmt.Errorf("create jwt manager: %w", err)
		}
		app.jwtManager = jm
	}

	// 限流器
	rl, err := ratelimit.NewRedisRateLimiter(
		app.redisClient.GetClient(),
		&ratelimit.RateLimiterConfig{
			DefaultLimit:  int64(app.config.RateLimit.GlobalRPM),
			DefaultWindow: app.config.RateLimit.WindowSize,
		},
		app.logger,
	)

	if err != nil {
		return fmt.Errorf("create rate limiter: %w", err)
	}

	app.rateLimiter = rl

	app.logger.Info(context.Background(), "Infrastructure components initialized")
	return nil
}

// initMonitoring 初始化监控组件
func (app *Application) initMonitoring() error {
	// Prometheus 指标
	app.metrics = monitoring.NewMetrics()

	app.logger.Info(context.Background(), "Monitoring components initialized")

	return nil
}

// initRepositories 初始化仓储实现
func (app *Application) initRepositories() error {
	// Token 仓储
	app.tokenRepo = postgres.NewTokenRepository(
		app.dbConn.DB(),
		app.logger,
	)

	// 设备仓储
	app.deviceRepo = postgres.NewDeviceRepository(
		app.dbConn.DB(),
		app.logger,
	)

	// 租户仓储
	app.tenantRepo = postgres.NewTenantRepository(
		app.dbConn.DB(),
		app.logger,
	)

	app.logger.Info(context.Background(), "Repositories initialized")
	return nil
}

// initApplicationServices 初始化应用服务
func (app *Application) initApplicationServices() error {
	// 认证应用服务
	app.authAppService = service.NewAuthAppService(
		domainService.NewTokenDomainService(app.tokenRepo, app.keyManager, app.logger),
		app.deviceRepo,
		app.tenantRepo,
		app.rateLimiter,
		app.logger,
	)

	// 设备应用服务
	app.deviceAppService = service.NewDeviceAppService(
		app.deviceRepo,
		app.logger,
	)

	// 租户应用服务
	app.tenantAppService = service.NewTenantAppService(
		app.tenantRepo,
		app.keyManager,
		app.logger,
	)

	app.logger.Info(context.Background(), "Application services initialized")
	return nil
}

// initInterfaces 初始化接口层
func (app *Application) initInterfaces() error {
	// 初始化 HTTP 服务
	if err := app.initHTTP(); err != nil {
		return fmt.Errorf("init http: %w", err)
	}

	// 初始化 gRPC 服务
	if err := app.initGRPC(); err != nil {
		return fmt.Errorf("init grpc: %w", err)
	}

	return nil
}

// initHTTP 初始化 HTTP 服务
func (app *Application) initHTTP() error {
	// 设置 Gin 模式
	gin.SetMode(gin.ReleaseMode)

	// 创建 Gin 引擎
	app.ginEngine = gin.New()

	// 创建 HTTP 处理器
	authHandler := handlers.NewAuthHandler(
		app.authAppService,
		handlers.NewMetricsAdapter(app.metrics),
		app.logger,
	)

	deviceHandler := handlers.NewDeviceHandler(
		app.deviceAppService,
		handlers.NewMetricsAdapter(app.metrics),
		app.logger,
	)

	healthHandler := handlers.NewHealthHandler(
		app.dbConn,
		app.redisClient,
		app.vaultClient,
		app.logger,
	)

	// 配置路由
	r := httpRouter.NewRouter(
		app.config,
		app.logger,
		healthHandler,
		authHandler,
		deviceHandler,
	)

	r.SetupRoutes(app.ginEngine)

	// 创建 HTTP 服务器
	httpPort := fmt.Sprintf("%d", app.config.Server.HTTPPort)
	if httpPort == "" {
		httpPort = DefaultHTTPPort
	}

	app.httpServer = &http.Server{
		Addr:         ":" + httpPort,
		Handler:      app.ginEngine,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	app.logger.Info(context.Background(), "HTTP interface initialized",
		logger.String("port", httpPort),
	)

	return nil
}

// initGRPC 初始化 gRPC 服务
func (app *Application) initGRPC() error {
	// 创建 gRPC 拦截器
	interceptors := grpcInterface.NewInterceptorChain(
		app.logger,
		app.rateLimiter,
	)

	// 创建 gRPC 服务器
	app.grpcServer = grpc.NewServer(
		interceptors.ChainUnaryInterceptors(),
	)

	// 注册 gRPC 服务
	authGRPCService := grpcInterface.NewAuthGRPCService(
		app.authAppService,
		app.logger,
	)

	authGRPCService.RegisterService(app.grpcServer)

	// 注册健康检查服务
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(app.grpcServer, healthServer)

	// 注册反射服务（开发环境）
	reflection.Register(app.grpcServer)

	// 创建监听器
	grpcPort := fmt.Sprintf("%d", app.config.Server.GRPCPort)
	if grpcPort == "" {
		grpcPort = DefaultGRPCPort
	}

	listener, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		return fmt.Errorf("listen grpc port: %w", err)
	}
	app.grpcListener = listener

	app.logger.Info(context.Background(), "gRPC interface initialized",
		logger.String("port", grpcPort),
	)

	return nil
}

// Start 启动应用
func (app *Application) Start() error {
	// 启动 HTTP 服务器
	go func() {
		app.logger.Info(context.Background(), "Starting HTTP server",
			logger.String("addr", app.httpServer.Addr),
		)

		if err := app.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Fatal(context.Background(), "HTTP server failed", err)
		}
	}()

	// 启动 gRPC 服务器
	go func() {
		app.logger.Info(context.Background(), "Starting gRPC server",
			logger.String("addr", app.grpcListener.Addr().String()),
		)

		if err := app.grpcServer.Serve(app.grpcListener); err != nil {
			app.logger.Fatal(context.Background(), "gRPC server failed", err)
		}
	}()

	// 启动 Prometheus 指标服务器
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		metricsServer := &http.Server{
			Addr:    ":9090",
			Handler: mux,
		}

		app.logger.Info(context.Background(), "Starting metrics server",
			logger.String("addr", metricsServer.Addr),
		)

		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Error(context.Background(), "Metrics server failed", err)
		}
	}()

	// 启动定时任务
	app.startScheduledTasks()

	app.logger.Info(context.Background(), "All services started successfully")
	return nil
}

// startScheduledTasks 启动定时任务
func (app *Application) startScheduledTasks() {
	// 清理过期 Token 的定时任务
	app.cleanupTicker = time.NewTicker(CleanupInterval)

	go func() {
		for {
			select {
			case <-app.cleanupTicker.C:
				app.logger.Info(context.Background(), "Running scheduled cleanup task")

				if err := app.cleanupExpiredTokens(); err != nil {
					app.logger.Error(context.Background(), "Cleanup task failed", err)
				} else {
					app.logger.Info(context.Background(), "Cleanup task completed successfully")
				}

			case <-app.ctx.Done():
				app.logger.Info(context.Background(), "Stopping scheduled tasks")
				return
			}
		}
	}()

	app.logger.Info(context.Background(), "Scheduled tasks started",
		logger.Duration("cleanup_interval", CleanupInterval),
	)
}

// cleanupExpiredTokens 清理过期 Token
func (app *Application) cleanupExpiredTokens() error {
	ctx, cancel := context.WithTimeout(app.ctx, 5*time.Minute)
	defer cancel()

	// 清理过期的 Token 元数据
	deletedCount, err := app.tokenRepo.DeleteExpired(ctx, time.Now())
	if err != nil {
		return fmt.Errorf("delete expired tokens: %w", err)
	}

	app.logger.Info(context.Background(), "Expired tokens cleaned",
		logger.Int64("deleted_count", deletedCount),
	)

	return nil
}

// WaitForShutdown 等待系统信号
func (app *Application) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	app.logger.Info(context.Background(), "Received shutdown signal",
		logger.String("signal", sig.String()),
	)
}

// Shutdown 优雅关闭应用
func (app *Application) Shutdown() error {
	app.logger.Info(context.Background(), "Shutting down application...")

	// 创建关闭超时上下文
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()

	// 停止接受新请求
	app.logger.Info(context.Background(), "Stopping HTTP server...")
	if err := app.httpServer.Shutdown(shutdownCtx); err != nil {
		app.logger.Error(context.Background(), "HTTP server shutdown error", err)
	}

	app.logger.Info(context.Background(), "Stopping gRPC server...")
	app.grpcServer.GracefulStop()

	// 停止定时任务
	if app.cleanupTicker != nil {
		app.cleanupTicker.Stop()
	}

	// 取消上下文
	app.cancel()

	// 关闭数据库连接
	if app.dbConn != nil {
		app.logger.Info(context.Background(), "Closing PostgreSQL connections...")
		app.dbConn.Close()
	}

	if app.redisClient != nil {
		app.logger.Info(context.Background(), "Closing Redis connections...")
		if err := app.redisClient.Close(); err != nil {
			app.logger.Error(context.Background(), "Redis close error", err)
		}
	}

	// 关闭 Vault 客户端
	if app.vaultClient != nil {
		if err := app.vaultClient.Close(); err != nil {
			app.logger.Error(context.Background(), "Vault client close error", err)
		}
	}

	app.logger.Info(context.Background(), "Application shutdown completed")
	return nil
}
