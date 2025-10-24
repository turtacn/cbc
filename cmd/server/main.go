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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	// 应用层
	"github.com/turtacn/cbc/internal/application/service"

	// 配置层
	"github.com/turtacn/cbc/internal/config"

	// 领域层
	domainService "github.com/turtacn/cbc/internal/domain/service"

	// 基础设施层
	"github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	redisInfra "github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/internal/infrastructure/ratelimit"

	// 接口层
	"github.com/turtacn/cbc/internal/interfaces/grpc"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/internal/interfaces/http/router"

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
	pgPool      *pgxpool.Pool
	redisClient *redis.ClusterClient

	// 基础设施组件
	vaultClient  *crypto.VaultClient
	cacheManager *redisInfra.CacheManager
	keyManager   *crypto.KeyManager
	jwtManager   *crypto.JWTManager
	rateLimiter  domainService.RateLimitService

	// 监控组件
	metrics *monitoring.Metrics
	tracer  *monitoring.Tracer

	// 仓储实现
	tokenRepo  *postgres.TokenRepositoryImpl
	deviceRepo *postgres.DeviceRepositoryImpl
	tenantRepo *postgres.TenantRepositoryImpl

	// 应用服务
	authAppService   *service.AuthAppService
	deviceAppService *service.DeviceAppService
	tenantAppService *service.TenantAppService

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

func main() {
	// 创建应用实例
	app, err := NewApplication()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize application: %v\n", err)
		os.Exit(1)
	}

	// 启动应用
	if err := app.Start(); err != nil {
		app.logger.Error("Failed to start application", zap.Error(err))
		os.Exit(1)
	}

	// 等待系统信号
	app.WaitForShutdown()

	// 优雅关闭
	if err := app.Shutdown(); err != nil {
		app.logger.Error("Failed to shutdown gracefully", zap.Error(err))
		os.Exit(1)
	}

	app.logger.Info("Application stopped successfully")
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

	app.logger.Info("Starting CBC Auth Service",
		zap.String("version", ServiceVersion),
		zap.String("environment", app.config.Environment),
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
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}

	app.config = cfg
	return nil
}

// initLogger 初始化日志
func (app *Application) initLogger() error {
	log, err := logger.NewZapLogger(
		app.config.Logger.Level,
		app.config.Logger.Format,
		app.config.Logger.OutputPaths,
	)
	if err != nil {
		return err
	}

	app.logger = log
	return nil
}

// initDatabase 初始化数据库连接
func (app *Application) initDatabase() error {
	// PostgreSQL 连接池
	pgPool, err := postgres.NewConnectionPool(
		app.ctx,
		app.config.Database.PostgreSQL.DSN,
		app.config.Database.PostgreSQL.MaxConns,
		app.config.Database.PostgreSQL.MinConns,
	)
	if err != nil {
		return fmt.Errorf("create postgres pool: %w", err)
	}
	app.pgPool = pgPool

	// 验证连接
	if err := pgPool.Ping(app.ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}

	app.logger.Info("PostgreSQL connected",
		zap.String("host", app.config.Database.PostgreSQL.Host),
		zap.Int("max_conns", app.config.Database.PostgreSQL.MaxConns),
	)

	// Redis 集群客户端
	redisClient, err := redisInfra.NewClusterClient(
		app.config.Database.Redis.Addrs,
		app.config.Database.Redis.Password,
		app.config.Database.Redis.PoolSize,
	)
	if err != nil {
		return fmt.Errorf("create redis client: %w", err)
	}
	app.redisClient = redisClient

	// 验证连接
	if err := redisClient.Ping(app.ctx).Err(); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}

	app.logger.Info("Redis cluster connected",
		zap.Strings("addrs", app.config.Database.Redis.Addrs),
		zap.Int("pool_size", app.config.Database.Redis.PoolSize),
	)

	return nil
}

// initVault 初始化 Vault 客户端
func (app *Application) initVault() error {
	vaultClient, err := crypto.NewVaultClient(
		app.config.Vault.Address,
		app.config.Vault.Token,
		app.config.Vault.Namespace,
	)
	if err != nil {
		return fmt.Errorf("create vault client: %w", err)
	}

	app.vaultClient = vaultClient

	// 验证连接
	if err := vaultClient.Ping(app.ctx); err != nil {
		return fmt.Errorf("ping vault: %w", err)
	}

	app.logger.Info("Vault connected",
		zap.String("address", app.config.Vault.Address),
	)

	return nil
}

// initInfrastructure 初始化基础设施组件
func (app *Application) initInfrastructure() error {
	// 缓存管理器
	app.cacheManager = redisInfra.NewCacheManager(
		app.redisClient,
		app.logger,
	)

	// 密钥管理器
	app.keyManager = crypto.NewKeyManager(
		app.vaultClient,
		app.cacheManager,
		app.logger,
	)

	// JWT 管理器
	app.jwtManager = crypto.NewJWTManager(
		app.keyManager,
		app.logger,
	)

	// 限流器
	app.rateLimiter = ratelimit.NewRedisRateLimiter(
		app.redisClient,
		app.logger,
	)

	app.logger.Info("Infrastructure components initialized")
	return nil
}

// initMonitoring 初始化监控组件
func (app *Application) initMonitoring() error {
	// Prometheus 指标
	app.metrics = monitoring.NewMetrics(ServiceName)

	// OpenTelemetry 追踪
	tracer, err := monitoring.NewTracer(
		app.ctx,
		ServiceName,
		ServiceVersion,
		app.config.Monitoring.Tracing.Endpoint,
	)
	if err != nil {
		return fmt.Errorf("create tracer: %w", err)
	}
	app.tracer = tracer

	app.logger.Info("Monitoring components initialized",
		zap.String("tracing_endpoint", app.config.Monitoring.Tracing.Endpoint),
	)

	return nil
}

// initRepositories 初始化仓储实现
func (app *Application) initRepositories() error {
	// Token 仓储
	app.tokenRepo = postgres.NewTokenRepository(
		app.pgPool,
		app.logger,
	)

	// 设备仓储
	app.deviceRepo = postgres.NewDeviceRepository(
		app.pgPool,
		app.logger,
	)

	// 租户仓储
	app.tenantRepo = postgres.NewTenantRepository(
		app.pgPool,
		app.logger,
	)

	app.logger.Info("Repositories initialized")
	return nil
}

// initApplicationServices 初始化应用服务
func (app *Application) initApplicationServices() error {
	// 认证应用服务
	app.authAppService = service.NewAuthAppService(
		app.tokenRepo,
		app.deviceRepo,
		app.tenantRepo,
		app.jwtManager,
		app.rateLimiter,
		app.cacheManager,
		app.metrics,
		app.logger,
	)

	// 设备应用服务
	app.deviceAppService = service.NewDeviceAppService(
		app.deviceRepo,
		app.tenantRepo,
		app.cacheManager,
		app.logger,
	)

	// 租户应用服务
	app.tenantAppService = service.NewTenantAppService(
		app.tenantRepo,
		app.keyManager,
		app.cacheManager,
		app.logger,
	)

	app.logger.Info("Application services initialized")
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
	if app.config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// 创建 Gin 引擎
	app.ginEngine = gin.New()

	// 创建 HTTP 处理器
	authHandler := handlers.NewAuthHandler(
		app.authAppService,
		app.logger,
	)

	deviceHandler := handlers.NewDeviceHandler(
		app.deviceAppService,
		app.logger,
	)

	healthHandler := handlers.NewHealthHandler(
		app.pgPool,
		app.redisClient,
		app.vaultClient,
		app.logger,
	)

	// 配置路由
	router.SetupRoutes(
		app.ginEngine,
		authHandler,
		deviceHandler,
		healthHandler,
		app.metrics,
		app.tracer,
		app.logger,
	)

	// 创建 HTTP 服务器
	httpPort := app.config.Server.HTTPPort
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

	app.logger.Info("HTTP interface initialized",
		zap.String("port", httpPort),
	)

	return nil
}

// initGRPC 初始化 gRPC 服务
func (app *Application) initGRPC() error {
	// 创建 gRPC 拦截器
	interceptors := grpcInterface.NewInterceptors(
		app.metrics,
		app.tracer,
		app.logger,
	)

	// 创建 gRPC 服务器
	app.grpcServer = grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interceptors.UnaryLoggingInterceptor(),
			interceptors.UnaryMetricsInterceptor(),
			interceptors.UnaryTracingInterceptor(),
			interceptors.UnaryRecoveryInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			interceptors.StreamLoggingInterceptor(),
			interceptors.StreamMetricsInterceptor(),
			interceptors.StreamTracingInterceptor(),
		),
	)

	// 注册 gRPC 服务
	authGRPCService := grpcInterface.NewAuthGRPCService(
		app.authAppService,
		app.logger,
	)

	grpcInterface.RegisterAuthServiceServer(app.grpcServer, authGRPCService)

	// 注册健康检查服务
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(app.grpcServer, healthServer)

	// 注册反射服务（开发环境）
	if app.config.Environment != "production" {
		reflection.Register(app.grpcServer)
	}

	// 创建监听器
	grpcPort := app.config.Server.GRPCPort
	if grpcPort == "" {
		grpcPort = DefaultGRPCPort
	}

	listener, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		return fmt.Errorf("listen grpc port: %w", err)
	}
	app.grpcListener = listener

	app.logger.Info("gRPC interface initialized",
		zap.String("port", grpcPort),
	)

	return nil
}

// Start 启动应用
func (app *Application) Start() error {
	// 启动 HTTP 服务器
	go func() {
		app.logger.Info("Starting HTTP server",
			zap.String("addr", app.httpServer.Addr),
		)

		if err := app.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Fatal("HTTP server failed", zap.Error(err))
		}
	}()

	// 启动 gRPC 服务器
	go func() {
		app.logger.Info("Starting gRPC server",
			zap.String("addr", app.grpcListener.Addr().String()),
		)

		if err := app.grpcServer.Serve(app.grpcListener); err != nil {
			app.logger.Fatal("gRPC server failed", zap.Error(err))
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

		app.logger.Info("Starting metrics server",
			zap.String("addr", metricsServer.Addr),
		)

		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Error("Metrics server failed", zap.Error(err))
		}
	}()

	// 启动定时任务
	app.startScheduledTasks()

	app.logger.Info("All services started successfully")
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
				app.logger.Info("Running scheduled cleanup task")

				if err := app.cleanupExpiredTokens(); err != nil {
					app.logger.Error("Cleanup task failed", zap.Error(err))
				} else {
					app.logger.Info("Cleanup task completed successfully")
				}

			case <-app.ctx.Done():
				app.logger.Info("Stopping scheduled tasks")
				return
			}
		}
	}()

	app.logger.Info("Scheduled tasks started",
		zap.Duration("cleanup_interval", CleanupInterval),
	)
}

// cleanupExpiredTokens 清理过期 Token
func (app *Application) cleanupExpiredTokens() error {
	ctx, cancel := context.WithTimeout(app.ctx, 5*time.Minute)
	defer cancel()

	// 清理过期的 Token 元数据
	deletedCount, err := app.tokenRepo.DeleteExpiredTokens(ctx, time.Now())
	if err != nil {
		return fmt.Errorf("delete expired tokens: %w", err)
	}

	app.logger.Info("Expired tokens cleaned",
		zap.Int64("deleted_count", deletedCount),
	)

	// 清理过期的黑名单条目
	if err := app.cacheManager.CleanupExpiredBlacklist(ctx); err != nil {
		return fmt.Errorf("cleanup expired blacklist: %w", err)
	}

	return nil
}

// WaitForShutdown 等待系统信号
func (app *Application) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	app.logger.Info("Received shutdown signal",
		zap.String("signal", sig.String()),
	)
}

// Shutdown 优雅关闭应用
func (app *Application) Shutdown() error {
	app.logger.Info("Shutting down application...")

	// 创建关闭超时上下文
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()

	// 停止接受新请求
	app.logger.Info("Stopping HTTP server...")
	if err := app.httpServer.Shutdown(shutdownCtx); err != nil {
		app.logger.Error("HTTP server shutdown error", zap.Error(err))
	}

	app.logger.Info("Stopping gRPC server...")
	app.grpcServer.GracefulStop()

	// 停止定时任务
	if app.cleanupTicker != nil {
		app.cleanupTicker.Stop()
	}

	// 取消上下文
	app.cancel()

	// 关闭监控组件
	if app.tracer != nil {
		if err := app.tracer.Shutdown(shutdownCtx); err != nil {
			app.logger.Error("Tracer shutdown error", zap.Error(err))
		}
	}

	// 关闭数据库连接
	if app.pgPool != nil {
		app.logger.Info("Closing PostgreSQL connections...")
		app.pgPool.Close()
	}

	if app.redisClient != nil {
		app.logger.Info("Closing Redis connections...")
		if err := app.redisClient.Close(); err != nil {
			app.logger.Error("Redis close error", zap.Error(err))
		}
	}

	// 关闭 Vault 客户端
	if app.vaultClient != nil {
		if err := app.vaultClient.Close(); err != nil {
			app.logger.Error("Vault client close error", zap.Error(err))
		}
	}

	app.logger.Info("Application shutdown completed")
	return nil
}

//Personal.AI order the ending
