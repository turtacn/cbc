//go:build !test

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"go.opentelemetry.io/otel"
	"github.com/hashicorp/vault/api"

	// Adapters
	ratelimitadapter "github.com/turtacn/cbc/internal/adapter/ratelimit"

	// Application Layer
	"github.com/turtacn/cbc/internal/application"
	"github.com/turtacn/cbc/internal/application/service"

	// Configuration
	"github.com/turtacn/cbc/internal/config"

	// Domain Layer
	"github.com/turtacn/cbc/internal/domain/repository"
	domainService "github.com/turtacn/cbc/internal/domain/service"

	// Infrastructure Layer
	"github.com/turtacn/cbc/internal/infrastructure/audit"
	"github.com/turtacn/cbc/internal/infrastructure/cdn"
	"github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/internal/infrastructure/kms"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	infraPostgres "github.com/turtacn/cbc/internal/infrastructure/postgres"
	redisInfra "github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/internal/infrastructure/policy"
	"github.com/turtacn/cbc/internal/infrastructure/ratelimit"
	redisStore "github.com/turtacn/cbc/internal/infrastructure/redis"

	// Interface Layer
	grpcInterface "github.com/turtacn/cbc/internal/interfaces/grpc"
	authpb "github.com/turtacn/cbc/internal/interfaces/grpc/proto"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/internal/interfaces/http/middleware"
	httpRouter "github.com/turtacn/cbc/internal/interfaces/http/router"

	// Common Packages
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/redis/go-redis/v9"
)

const (
	// ServiceName is the official name of the service.
	// ServiceName 是服务的正式名称。
	ServiceName = "cbc-auth-service"
	// ServiceVersion is the current version of the service.
	// ServiceVersion 是服务的当前版本。
	ServiceVersion = "v1.2.0"
	// DefaultHTTPPort is the port used for the main HTTP server if not specified in the config.
	// DefaultHTTPPort 是未在配置中指定时用于主 HTTP 服务器的端口。
	DefaultHTTPPort = "8080"
	// DefaultGRPCPort is the port used for the gRPC server if not specified in the config.
	// DefaultGRPCPort 是未在配置中指定时用于 gRPC 服务器的端口。
	DefaultGRPCPort = "50051"
	// ShutdownTimeout is the maximum time to wait for graceful shutdown.
	// ShutdownTimeout 是等待正常关闭的最长时间。
	ShutdownTimeout = 30 * time.Second
	// CleanupInterval is the interval for periodic background cleanup tasks.
	// CleanupInterval 是定期后台清理任务的间隔。
	CleanupInterval = 1 * time.Hour
)

// Application holds all the major components of the service, including servers,
// database connections, and all layers of the domain-driven design architecture.
// Application 包含服务的所有主要组件，包括服务器、数据库连接以及领域驱动设计架构的所有层。
type Application struct {
	config               *config.Config
	logger               logger.Logger
	dbConn               *postgres.DBConnection
	redisClient          *redisInfra.RedisConnection
	cacheManager         *redisInfra.CacheManager
	keyManager           *crypto.KeyManager
	rateLimiter          *ratelimit.RedisRateLimiter
	vaultClient          *api.Client
	auditService         domainService.AuditService
	kms                  domainService.KeyManagementService
	cdnManager           domainService.CDNCacheManager
	rateLimitService     domainService.RateLimitService
	policyService        domainService.PolicyService
	mgrKeyFetcher        domainService.MgrKeyFetcher
	blacklistStore       domainService.TokenBlacklistStore
	metrics              *monitoring.Metrics
	tokenRepo            repository.TokenRepository
	deviceRepo           repository.DeviceRepository
	tenantRepo           repository.TenantRepository
	keyRepo              repository.KeyRepository
	riskRepo             repository.RiskRepository
	authAppService       service.AuthAppService
	deviceAppService     service.DeviceAppService
	deviceAuthAppService service.DeviceAuthAppService
	tenantAppService     service.TenantAppService
	httpServer           *http.Server
	internalHTTPServer   *http.Server
	grpcServer           *grpc.Server
	ctx                  context.Context
	cancel               context.CancelFunc
}

// main is the entry point for the cbc-auth-service.
// It creates a new application, starts it, waits for a shutdown signal, and then gracefully shuts down.
// main 是 cbc-auth-service 的入口点。
// 它创建一个新的应用程序，启动它，等待关闭信号，然后正常关闭。
func main() {
	app, err := NewApplication()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize application: %v\n", err)
		os.Exit(1)
	}
	if err := app.Start(); err != nil {
		app.logger.Error(context.Background(), "Failed to start application", err)
		os.Exit(1)
	}
	app.WaitForShutdown()
	if err := app.Shutdown(); err != nil {
		app.logger.Error(context.Background(), "Failed to shut down gracefully", err)
		os.Exit(1)
	}
}

// NewApplication creates and initializes a new Application instance.
// It follows a series of initialization steps to load configuration, set up logging,
// connect to databases, and wire up all the application layers.
// NewApplication 创建并初始化一个新的 Application 实例。
// 它遵循一系列初始化步骤来加载配置、设置日志记录、连接到数据库以及连接所有应用程序层。
func NewApplication() (*Application, error) {
	ctx, cancel := context.WithCancel(context.Background())
	app := &Application{ctx: ctx, cancel: cancel}
	initSteps := []func() error{
		app.loadConfig,
		app.initLogger,
		app.initDatabase,
		app.initVault,
		app.initInfrastructure,
		app.initDomainServices,
		app.initMonitoring,
		app.initRepositories,
		app.initApplicationServices,
		app.initInterfaces,
	}
	for _, step := range initSteps {
		if err := step(); err != nil {
			cancel() // Ensure context is cancelled on initialization failure.
			return nil, err
		}
	}
	app.logger.Info(context.Background(), "Application initialized successfully", logger.String("version", ServiceVersion))
	return app, nil
}

// loadConfig loads the application configuration from file or environment variables.
// loadConfig 从文件或环境变量加载应用程序配置。
func (app *Application) loadConfig() error {
	cfg, err := config.NewLoader().Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	app.config = cfg
	return nil
}

// initLogger initializes the application's logger.
// initLogger 初始化应用程序的记录器。
func (app *Application) initLogger() error {
	app.logger = logger.NewDefaultLogger()
	return nil
}

// initDatabase connects to the primary PostgreSQL database and the Redis instance.
// initDatabase 连接到主 PostgreSQL 数据库和 Redis 实例。
func (app *Application) initDatabase() error {
	// Initialize PostgreSQL connection
	dbConn, err := postgres.NewDBConnection(app.ctx, &app.config.Database, app.logger)
	if err != nil {
		return fmt.Errorf("failed to connect to postgres: %w", err)
	}
	if err := dbConn.Ping(app.ctx); err != nil {
		return fmt.Errorf("failed to ping postgres: %w", err)
	}
	app.dbConn = dbConn
	app.logger.Info(app.ctx, "PostgreSQL connection established")

	// Initialize Redis connection
	var redisCfg *redisInfra.Config
	if app.config.Redis.ClusterEnabled {
		redisCfg = &redisInfra.Config{
			Mode:         redisInfra.ModeCluster,
			ClusterAddrs: app.config.Redis.ClusterAddrs,
		}
	} else {
		host, portStr, err := net.SplitHostPort(app.config.Redis.Address)
		if err != nil {
			return fmt.Errorf("failed to parse redis address '%s': %w", app.config.Redis.Address, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("failed to parse redis port '%s': %w", portStr, err)
		}

		redisCfg = &redisInfra.Config{
			Mode: redisInfra.ModeStandalone,
			Host: host,
			Port: port,
			DB:   app.config.Redis.DB,
		}
	}

	// Common settings from app.config.Redis to redisInfra.Config
	redisCfg.Password = app.config.Redis.Password
	redisCfg.PoolSize = app.config.Redis.PoolSize
	redisCfg.MinIdleConns = app.config.Redis.MinIdleConns
	redisCfg.MaxIdleTime = app.config.Redis.ConnMaxIdleTime
	redisCfg.DialTimeout = app.config.Redis.DialTimeout
	redisCfg.ReadTimeout = app.config.Redis.ReadTimeout
	redisCfg.WriteTimeout = app.config.Redis.WriteTimeout
	redisCfg.MaxRetries = app.config.Redis.MaxRetries

	redisConn := redisInfra.NewRedisConnection(redisCfg, app.logger)
	if err := redisConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to redis: %w", err)
	}
	if err := redisConn.Ping(app.ctx); err != nil {
		return fmt.Errorf("failed to ping redis: %w", err)
	}
	app.redisClient = redisConn
	app.logger.Info(app.ctx, "Redis connection established")
	return nil
}

// initVault initializes the client for interacting with HashiCorp Vault.
// initVault 初始化用于与 HashiCorp Vault 交互的客户端。
func (app *Application) initVault() error {
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = app.config.Vault.Address
	vaultConfig.Timeout = app.config.Vault.Timeout

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}
	client.SetToken(app.config.Vault.Token)
	app.vaultClient = client
	app.logger.Info(app.ctx, "Vault client initialized")
	return nil
}

// initInfrastructure initializes core infrastructure components like caching, key management, and rate limiting.
// initInfrastructure 初始化核心基础架构组件，如缓存、密钥管理和速率限制。
func (app *Application) initInfrastructure() error {
	app.cacheManager = redisInfra.NewCacheManager(app.redisClient.GetClient(), "cbc:", 1*time.Hour, app.logger)
	km, err := crypto.NewKeyManager(app.logger)
	if err != nil {
		return fmt.Errorf("failed to create key manager: %w", err)
	}
	app.keyManager = km
	rl, err := ratelimit.NewRedisRateLimiter(app.redisClient.GetClient(), &ratelimit.RateLimiterConfig{}, app.logger)
	if err != nil {
		return fmt.Errorf("failed to create rate limiter: %w", err)
	}
	app.rateLimiter = rl
	app.logger.Info(app.ctx, "Infrastructure components initialized")
	return nil
}

// initDomainServices initializes the domain-layer services and their dependencies.
// initDomainServices 初始化领域层服务及其依赖项。
func (app *Application) initDomainServices() error {
	var err error
	redisClient, ok := app.redisClient.GetClient().(redis.UniversalClient)
	if !ok {
		return fmt.Errorf("unexpected redis client type: %T", app.redisClient.GetClient())
	}

	vaultProvider, err := kms.NewVaultProvider(app.config.Vault, app.vaultClient, app.logger)
	if err != nil {
		return fmt.Errorf("failed to create vault provider: %w", err)
	}
	keyProviders := map[string]domainService.KeyProvider{"vault": vaultProvider}

	klr := infraPostgres.NewKLRRepository(app.dbConn.DB())
	policyEngine, err := policy.NewStaticPolicyEngine(app.config.Policy.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("failed to create policy engine: %w", err)
	}

	riskOracle := application.NewRiskOracle(app.riskRepo)
	app.kms, err = application.NewKeyManagementService(keyProviders, app.keyRepo, app.tenantRepo, policyEngine, klr, app.logger, riskOracle)
	if err != nil {
		return fmt.Errorf("failed to create key management service: %w", err)
	}

	if app.config.CDN.PurgeEnabled && app.config.CDN.Provider == "aws_cloudfront" {
		app.cdnManager, err = cdn.NewAWSCloudFrontAdapter(app.ctx, app.config.CDN.DistributionID, app.logger)
	if err != nil {
		return fmt.Errorf("failed to create aws cloudfront adapter: %w", err)
	}
	} else {
		app.cdnManager = cdn.NewStubAdapter(app.logger)
	}

	app.auditService, err = audit.NewKafkaProducer(app.config.Kafka, app.logger)
	if err != nil {
		return fmt.Errorf("failed to create kafka producer: %w", err)
	}

	app.rateLimitService = &ratelimitadapter.ServiceAdapter{RL: app.rateLimiter}
	app.blacklistStore = redisStore.NewTokenBlacklistStore(redisClient)
	// The stub policy service is only for testing, so we pass nil here.
	// A real implementation would be instantiated here.
	app.policyService = nil
	app.mgrKeyFetcher = kms.NewMgrKeyFetcher(app.vaultClient, redisClient)

	app.logger.Info(app.ctx, "Domain services initialized")
	return nil
}

// initMonitoring initializes the monitoring components, including Prometheus metrics and OpenTelemetry tracing.
// initMonitoring 初始化监控组件，包括 Prometheus 指标和 OpenTelemetry 跟踪。
func (app *Application) initMonitoring() error {
	app.metrics = monitoring.NewMetrics(prometheus.DefaultRegisterer)
	_, err := monitoring.NewTracingManager(app.config, app.logger)
	if err != nil {
		return fmt.Errorf("failed to create tracing manager: %w", err)
	}
	app.logger.Info(app.ctx, "Monitoring components initialized")
	return nil
}

// initRepositories initializes all the data repositories.
// initRepositories 初始化所有数据存储库。
func (app *Application) initRepositories() error {
	db := app.dbConn.DB()
	app.tokenRepo = postgres.NewTokenRepository(db, app.logger)
	app.deviceRepo = postgres.NewDeviceRepository(db, app.logger)
	app.tenantRepo = postgres.NewTenantRepository(db, app.logger)
	app.keyRepo = postgres.NewKeyRepository(db)
	app.riskRepo = infraPostgres.NewPostgresRiskRepository(db)
	app.logger.Info(app.ctx, "Repositories initialized")
	return nil
}

// initApplicationServices initializes the application-layer services, which orchestrate the domain logic.
// initApplicationServices 初始化应用层服务，这些服务负责协调领域逻辑。
func (app *Application) initApplicationServices() error {
	tokenDomainService := domainService.NewTokenDomainService(app.tokenRepo, app.kms, app.logger)

	redisClient, ok := app.redisClient.GetClient().(redis.UniversalClient)
	if !ok {
		return fmt.Errorf("unexpected redis client type: %T", app.redisClient.GetClient())
	}
	deviceAuthStore := redisStore.NewRedisDeviceAuthStore(redisClient)

	riskOracle := application.NewRiskOracle(app.riskRepo)
	policyEngine, err := policy.NewStaticPolicyEngine(app.config.Policy.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("failed to create policy engine: %w", err)
	}
	metricsAdapter := monitoring.NewMetricsAdapter(app.metrics)

	app.authAppService = service.NewAuthAppService(tokenDomainService, app.deviceRepo, app.tenantRepo, app.rateLimitService, app.blacklistStore, app.auditService, riskOracle, policyEngine, app.logger, metricsAdapter)
	app.deviceAuthAppService = service.NewDeviceAuthAppService(deviceAuthStore, tokenDomainService, app.kms, &app.config.OAuth, app.deviceRepo, app.tenantRepo, app.rateLimitService, app.auditService, app.logger)
	app.deviceAppService = service.NewDeviceAppService(app.deviceRepo, app.auditService, app.mgrKeyFetcher, app.policyService, tokenDomainService, app.blacklistStore, app.config, app.logger)
	app.tenantAppService = service.NewTenantAppService(app.tenantRepo, app.kms, app.cdnManager, app.logger)
	app.logger.Info(app.ctx, "Application services initialized")
	return nil
}

// initInterfaces initializes the transport layer, including the HTTP and gRPC servers, routers, handlers, and middleware.
// initInterfaces 初始化传输层，包括 HTTP 和 gRPC 服务器、路由器、处理程序和中间件。
func (app *Application) initInterfaces() error {
	tlsConfig, err := app.setupTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to setup TLS config: %w", err)
	}

	// Initialize main HTTP Server
	httpPort := fmt.Sprintf(":%d", app.config.Server.HTTPPort)
	if app.config.Server.HTTPPort == 0 {
		httpPort = ":" + DefaultHTTPPort
	}
	authHandler := handlers.NewAuthHandler(app.authAppService, app.deviceAuthAppService, app.logger)
	oauthHandler := handlers.NewOAuthHandler(app.deviceAuthAppService)
	deviceHandler := handlers.NewDeviceHandler(app.deviceAppService, app.logger)
	healthHandler := handlers.NewHealthHandler(app.dbConn, app.redisClient, app.logger)
	jwksHandler := handlers.NewJWKSHandler(app.kms, app.logger)

	// Initialize Middleware
	authMiddleware := middleware.RequireJWT(app.kms, app.blacklistStore, app.logger)
	rateLimitMiddleware := middleware.RateLimitMiddleware(app.rateLimitService, &app.config.RateLimit, app.logger)
	idempotencyMiddleware := middleware.IdempotencyMiddleware(app.redisClient.GetClient(), &app.config.Idempotency, app.logger)
	observabilityMiddleware := middleware.ObservabilityMiddleware(otel.Tracer(ServiceName), app.metrics.HTTPRequestsTotal, app.metrics.HTTPRequestDuration)

	router := httpRouter.NewRouter(app.config, app.logger, healthHandler, authHandler, deviceHandler, jwksHandler, oauthHandler, authMiddleware, rateLimitMiddleware, idempotencyMiddleware, observabilityMiddleware)
	router.SetupRoutes()
	app.httpServer = &http.Server{Addr: httpPort, Handler: router.Engine(), TLSConfig: tlsConfig}
	app.logger.Info(app.ctx, "Main HTTP interface initialized", logger.String("port", httpPort))

	// Initialize Internal HTTP Server for ML Risk Updates
	internalHTTPPort := fmt.Sprintf(":%d", app.config.Server.InternalHTTPPort)
	riskUpdateService := application.NewRiskUpdateService(app.riskRepo)
	mlInternalHandler := handlers.NewMLInternalHandler(riskUpdateService)
	internalRouter := httpRouter.NewInternalRouter(mlInternalHandler)
	internalRouter.SetupRoutes()
	app.internalHTTPServer = &http.Server{Addr: internalHTTPPort, Handler: internalRouter.Engine()}
	app.logger.Info(app.ctx, "Internal HTTP interface initialized", logger.String("port", internalHTTPPort))

	// Initialize gRPC Server
	grpcPort := fmt.Sprintf(":%d", app.config.Server.GRPCPort)
	if app.config.Server.GRPCPort == 0 {
		grpcPort = ":" + DefaultGRPCPort
	}
	listener, err := net.Listen("tcp", grpcPort)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %s: %w", grpcPort, err)
	}
	var opts []grpc.ServerOption
	if tlsConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}
	app.grpcServer = grpc.NewServer(opts...)
	authGRPCService := grpcInterface.NewAuthGRPCService(app.authAppService, app.logger)
	authpb.RegisterAuthServiceServer(app.grpcServer, authGRPCService)
	grpc_health_v1.RegisterHealthServer(app.grpcServer, health.NewServer())
	reflection.Register(app.grpcServer) // Enable gRPC reflection for debugging.
	go func() {
		if err := app.grpcServer.Serve(listener); err != nil {
			app.logger.Error(app.ctx, "gRPC server failed to serve", err)
		}
	}()
	app.logger.Info(app.ctx, "gRPC interface initialized", logger.String("port", grpcPort))
	return nil
}

// setupTLSConfig builds a TLS configuration for the servers based on the application config.
// It supports both server-side TLS and mutual TLS (mTLS) if a client CA is provided.
// setupTLSConfig 根据应用程序配置为服务器构建 TLS 配置。
// 如果提供了客户端 CA，它同时支持服务器端 TLS 和双向 TLS (mTLS)。
func (app *Application) setupTLSConfig() (*tls.Config, error) {
	if !app.config.Server.TLS.Enabled {
		return nil, nil
	}

	serverCert, err := tls.LoadX509KeyPair(app.config.Server.TLS.CertFile, app.config.Server.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server TLS key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	// Configure mTLS if a client CA file is specified.
	if app.config.Server.TLS.ClientCAFile != "" {
		caCert, err := os.ReadFile(app.config.Server.TLS.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append client CA certificate to pool")
		}
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		app.logger.Info(app.ctx, "mTLS has been enabled for all servers")
	}

	return tlsConfig, nil
}

// Start launches all the application's servers (HTTP, internal HTTP, gRPC, metrics) in separate goroutines.
// Start 在单独的 goroutine 中启动所有应用程序的服务器（HTTP、内部 HTTP、gRPC、指标）。
func (app *Application) Start() error {
	// Start the main public-facing HTTP/S server.
	go func() {
		if app.config.Server.TLS.Enabled {
			app.logger.Info(app.ctx, "Starting HTTPS server")
			if err := app.httpServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				app.logger.Fatal(app.ctx, "HTTPS server crashed", err)
			}
		} else {
			app.logger.Info(app.ctx, "Starting HTTP server")
			if err := app.httpServer.ListenAndServe(); err != http.ErrServerClosed {
				app.logger.Fatal(app.ctx, "HTTP server crashed", err)
			}
		}
	}()

	// Start the internal HTTP server for admin/ML tasks.
	go func() {
		app.logger.Info(app.ctx, "Starting internal HTTP server")
		if err := app.internalHTTPServer.ListenAndServe(); err != http.ErrServerClosed {
			app.logger.Fatal(app.ctx, "Internal HTTP server crashed", err)
		}
	}()

	// Start the Prometheus metrics server.
	go func() {
		mux := http.NewServeMux()
		mux.Handle(app.config.Observability.MetricsEndpoint, promhttp.Handler())
		metricsAddr := fmt.Sprintf(":%d", app.config.Observability.PrometheusPort)
		if err := http.ListenAndServe(metricsAddr, mux); err != http.ErrServerClosed {
			app.logger.Error(app.ctx, "Metrics server crashed", err)
		}
	}()

	app.logger.Info(app.ctx, "All services have been started")
	return nil
}

// WaitForShutdown blocks until a termination signal (SIGINT or SIGTERM) is received.
// WaitForShutdown 阻塞直到收到终止信号（SIGINT 或 SIGTERM）。
func (app *Application) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	app.logger.Info(app.ctx, "Shutdown signal received, initiating graceful shutdown")
}

// Shutdown gracefully stops all running servers and closes database connections.
// It uses a context with a timeout to ensure shutdown doesn't hang indefinitely.
// Shutdown 正常停止所有正在运行的服务器并关闭数据库连接。
// 它使用带有超时的上下文来确保关闭不会无限期地挂起。
func (app *Application) Shutdown() error {
	app.logger.Info(app.ctx, "Shutting down application components...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()

	// Shutdown servers in parallel for speed.
	var shutdownErr error
	if err := app.httpServer.Shutdown(shutdownCtx); err != nil {
		app.logger.Error(shutdownCtx, "Main HTTP server shutdown error", err)
		shutdownErr = err
	}
	if err := app.internalHTTPServer.Shutdown(shutdownCtx); err != nil {
		app.logger.Error(shutdownCtx, "Internal HTTP server shutdown error", err)
		shutdownErr = err
	}
	app.grpcServer.GracefulStop()

	// Close database connections.
	if app.dbConn != nil {
		app.dbConn.Close()
	}
	if app.redisClient != nil {
		if err := app.redisClient.Close(); err != nil {
			app.logger.Error(shutdownCtx, "Redis client close error", err)
			shutdownErr = err
		}
	}
	app.logger.Info(shutdownCtx, "Application shutdown complete")
	return shutdownErr
}
