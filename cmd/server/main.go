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

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	// Adapters
	cryptoadapter "github.com/turtacn/cbc/internal/adapter/crypto"
	ratelimitadapter "github.com/turtacn/cbc/internal/adapter/ratelimit"

	// Application Layer
	"github.com/turtacn/cbc/internal/application/service"

	// Configuration
	"github.com/turtacn/cbc/internal/config"

	// Domain Layer
	"github.com/turtacn/cbc/internal/domain/repository"
	domainService "github.com/turtacn/cbc/internal/domain/service"

	// Infrastructure Layer
	"github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	redisInfra "github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/internal/infrastructure/ratelimit"

	// Interface Layer
	grpcInterface "github.com/turtacn/cbc/internal/interfaces/grpc"
	authpb "github.com/turtacn/cbc/internal/interfaces/grpc/proto"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	httpRouter "github.com/turtacn/cbc/internal/interfaces/http/router"

	// Common Packages
	"github.com/turtacn/cbc/pkg/logger"
)

// ... (constants and Application struct definition remain the same) ...

const (
	// Service Information
	ServiceName    = "cbc-auth-service"
	ServiceVersion = "v1.2.0"

	// Default Ports
	DefaultHTTPPort = "8080"
	DefaultGRPCPort = "50051"

	// Graceful Shutdown Timeout
	ShutdownTimeout = 30 * time.Second

	// Scheduled Task Interval
	CleanupInterval = 1 * time.Hour
)

// Application struct holds all application components.
type Application struct {
	config *config.Config
	logger logger.Logger

	// Connections
	dbConn      *postgres.DBConnection
	redisClient *redisInfra.RedisConnection

	// Infrastructure Components
	cacheManager *redisInfra.CacheManager
	keyManager   *crypto.KeyManager // Concrete implementation
	rateLimiter  *ratelimit.RedisRateLimiter

	// Domain Services (via Adapters)
	cryptoService    domainService.CryptoService
	rateLimitService domainService.RateLimitService

	// Monitoring
	metrics *monitoring.Metrics

	// Repositories
	tokenRepo  repository.TokenRepository
	deviceRepo repository.DeviceRepository
	tenantRepo repository.TenantRepository

	// Application Services
	authAppService   service.AuthAppService
	deviceAppService service.DeviceAppService
	tenantAppService service.TenantAppService

	// Servers
	httpServer *http.Server
	grpcServer *grpc.Server

	// Context for graceful shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

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
		app.logger.Error(context.Background(), "Failed to shutdown gracefully", err)
		os.Exit(1)
	}
}

// NewApplication creates and initializes a new application instance.
func NewApplication() (*Application, error) {
	ctx, cancel := context.WithCancel(context.Background())

	app := &Application{ctx: ctx, cancel: cancel}

	// Sequentially initialize components
	initSteps := []func() error{
		app.loadConfig,
		app.initLogger,
		app.initDatabase,
		app.initInfrastructure,
		app.initDomainServices,
		app.initMonitoring,
		app.initRepositories,
		app.initApplicationServices,
		app.initInterfaces,
	}

	for _, step := range initSteps {
		if err := step(); err != nil {
			cancel()
			return nil, err
		}
	}

	app.logger.Info(context.Background(), "Application initialized successfully", logger.String("version", ServiceVersion))
	return app, nil
}

func (app *Application) loadConfig() error {
	cfg, err := config.NewLoader().Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	app.config = cfg
	return nil
}

func (app *Application) initLogger() error {
	app.logger = logger.NewDefaultLogger() // Simplified logger
	return nil
}

func (app *Application) initDatabase() error {
	dbConn, err := postgres.NewDBConnection(app.ctx, &app.config.Database, app.logger)
	if err != nil {
		return fmt.Errorf("failed to connect to postgres: %w", err)
	}
	if err := dbConn.Ping(app.ctx); err != nil {
		return fmt.Errorf("failed to ping postgres: %w", err)
	}
	app.dbConn = dbConn
	app.logger.Info(app.ctx, "PostgreSQL connected")

	// Map config.RedisConfig to redis.Config
	redisCfg := &redisInfra.Config{
		Mode:         redisInfra.ModeStandalone,
		Host:         "localhost", // Assuming single node from config.Address
		Port:         6379,
		Password:     app.config.Redis.Password,
		DB:           app.config.Redis.DB,
		PoolSize:     app.config.Redis.PoolSize,
		MinIdleConns: app.config.Redis.MinIdleConns,
		DialTimeout:  app.config.Redis.DialTimeout,
		ReadTimeout:  app.config.Redis.ReadTimeout,
		WriteTimeout: app.config.Redis.WriteTimeout,
		ClusterAddrs: app.config.Redis.ClusterAddrs,
	}
	if app.config.Redis.ClusterEnabled {
		redisCfg.Mode = redisInfra.ModeCluster
	}

	redisConn := redisInfra.NewRedisConnection(redisCfg, app.logger)
	if err := redisConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to redis: %w", err)
	}
	if err := redisConn.Ping(app.ctx); err != nil {
		return fmt.Errorf("failed to ping redis: %w", err)
	}
	app.redisClient = redisConn
	app.logger.Info(app.ctx, "Redis connected")
	return nil
}

func (app *Application) initInfrastructure() error {
	app.cacheManager = redisInfra.NewCacheManager(app.redisClient.GetClient(), "cbc:", 1*time.Hour, app.logger)

	km, err := crypto.NewKeyManager(app.logger)
	if err != nil {
		return fmt.Errorf("failed to create key manager: %w", err)
	}
	app.keyManager = km // Store concrete type

	rl, err := ratelimit.NewRedisRateLimiter(app.redisClient.GetClient(), &ratelimit.RateLimiterConfig{}, app.logger)
	if err != nil {
		return fmt.Errorf("failed to create rate limiter: %w", err)
	}
	app.rateLimiter = rl

	app.logger.Info(app.ctx, "Infrastructure components initialized")
	return nil
}

func (app *Application) initDomainServices() error {
	// Adapters wire infrastructure components to domain interfaces
	app.cryptoService = cryptoadapter.NewServiceAdapter(app.keyManager, app.logger)
	app.rateLimitService = &ratelimitadapter.ServiceAdapter{RL: app.rateLimiter}
	app.logger.Info(app.ctx, "Domain services initialized via adapters")
	return nil
}

func (app *Application) initMonitoring() error {
	app.metrics = monitoring.NewMetrics()
	app.logger.Info(app.ctx, "Monitoring components initialized")
	return nil
}

func (app *Application) initRepositories() error {
	db := app.dbConn.DB()
	app.tokenRepo = postgres.NewTokenRepository(db, app.logger)
	app.deviceRepo = postgres.NewDeviceRepository(db, app.logger)
	app.tenantRepo = postgres.NewTenantRepository(db, app.logger)
	app.logger.Info(app.ctx, "Repositories initialized")
	return nil
}

func (app *Application) initApplicationServices() error {
	tokenDomainService := domainService.NewTokenDomainService(app.tokenRepo, app.cryptoService, app.logger)
	app.authAppService = service.NewAuthAppService(tokenDomainService, app.deviceRepo, app.tenantRepo, app.rateLimitService, app.logger)
	app.deviceAppService = service.NewDeviceAppService(app.deviceRepo, app.logger)
	app.tenantAppService = service.NewTenantAppService(app.tenantRepo, app.cryptoService, app.logger)
	app.logger.Info(app.ctx, "Application services initialized")
	return nil
}

func (app *Application) initInterfaces() error {
	// HTTP Server
	httpPort := fmt.Sprintf(":%d", app.config.Server.HTTPPort)
	if app.config.Server.HTTPPort == 0 {
		httpPort = ":" + DefaultHTTPPort
	}
	metricsAdapter := handlers.NewMetricsAdapter(app.metrics)
	authHandler := handlers.NewAuthHandler(app.authAppService, metricsAdapter, app.logger)
	deviceHandler := handlers.NewDeviceHandler(app.deviceAppService, metricsAdapter, app.logger)
	healthHandler := handlers.NewHealthHandler(app.dbConn, app.redisClient, nil, app.logger)
	// 构造 JWKS handler
	jwksHandler := handlers.NewJWKSHandler(app.cryptoService, app.logger, metricsAdapter)
	router := httpRouter.NewRouter(app.config, app.logger, healthHandler, authHandler, deviceHandler, jwksHandler)
	router.SetupRoutes()
	app.httpServer = &http.Server{Addr: httpPort, Handler: router.Engine()}
	app.logger.Info(app.ctx, "HTTP interface initialized", logger.String("port", httpPort))

	// gRPC Server
	grpcPort := fmt.Sprintf(":%d", app.config.Server.GRPCPort)
	if app.config.Server.GRPCPort == 0 {
		grpcPort = ":" + DefaultGRPCPort
	}
	listener, err := net.Listen("tcp", grpcPort)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port: %w", err)
	}
	app.grpcServer = grpc.NewServer()
	authGRPCService := grpcInterface.NewAuthGRPCService(app.authAppService, app.logger)
	authpb.RegisterAuthServiceServer(app.grpcServer, authGRPCService)
	grpc_health_v1.RegisterHealthServer(app.grpcServer, health.NewServer())
	reflection.Register(app.grpcServer)
	go func() {
		if err := app.grpcServer.Serve(listener); err != nil {
			app.logger.Error(app.ctx, "gRPC server failed", err)
		}
	}()
	app.logger.Info(app.ctx, "gRPC interface initialized", logger.String("port", grpcPort))
	return nil
}

// ... (Start, WaitForShutdown, and Shutdown methods remain the same) ...

// Start launches all background services.
func (app *Application) Start() error {
	// Start HTTP server
	go func() {
		if err := app.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			app.logger.Fatal(app.ctx, "HTTP server crashed", err)
		}
	}()

	// Start Prometheus metrics server
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(":9090", mux); err != http.ErrServerClosed {
			app.logger.Error(app.ctx, "Metrics server crashed", err)
		}
	}()
	app.logger.Info(app.ctx, "All services started")
	return nil
}

// WaitForShutdown blocks until a shutdown signal is received.
func (app *Application) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	app.logger.Info(app.ctx, "Shutdown signal received")
}

// Shutdown gracefully stops all application services.
func (app *Application) Shutdown() error {
	app.logger.Info(app.ctx, "Shutting down application...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()

	// Stop servers
	if err := app.httpServer.Shutdown(shutdownCtx); err != nil {
		app.logger.Error(shutdownCtx, "HTTP server shutdown error", err)
	}
	app.grpcServer.GracefulStop()

	// Close connections
	if app.dbConn != nil {
		app.dbConn.Close()
	}
	if app.redisClient != nil {
		if err := app.redisClient.Close(); err != nil {
			app.logger.Error(shutdownCtx, "Redis close error", err)
		}
	}
	app.logger.Info(shutdownCtx, "Application shutdown complete")
	return nil
}
