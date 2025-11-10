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
	ServiceName    = "cbc-auth-service"
	ServiceVersion = "v1.2.0"
	DefaultHTTPPort = "8080"
	DefaultGRPCPort = "50051"
	ShutdownTimeout = 30 * time.Second
	CleanupInterval = 1 * time.Hour
)

type Application struct {
	config *config.Config
	logger logger.Logger
	dbConn *postgres.DBConnection
	redisClient *redisInfra.RedisConnection
	cacheManager *redisInfra.CacheManager
	keyManager *crypto.KeyManager
	rateLimiter *ratelimit.RedisRateLimiter
	vaultClient *api.Client
	auditService domainService.AuditService
	kms domainService.KeyManagementService
	cdnManager domainService.CDNCacheManager
	rateLimitService domainService.RateLimitService
	policyService domainService.PolicyService
	mgrKeyFetcher domainService.MgrKeyFetcher
	blacklistStore domainService.TokenBlacklistStore
	metrics *monitoring.Metrics
	tokenRepo repository.TokenRepository
	deviceRepo repository.DeviceRepository
	tenantRepo repository.TenantRepository
	keyRepo repository.KeyRepository
	authAppService service.AuthAppService
	deviceAppService service.DeviceAppService
	deviceAuthAppService service.DeviceAuthAppService
	tenantAppService service.TenantAppService
	httpServer *http.Server
	internalHTTPServer *http.Server
	grpcServer *grpc.Server
	ctx context.Context
	cancel context.CancelFunc
	riskRepo repository.RiskRepository
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
	app.logger = logger.NewDefaultLogger()
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
	redisCfg := &redisInfra.Config{
		Mode: redisInfra.ModeStandalone,
		Host: "localhost",
		Port: 6379,
		Password: app.config.Redis.Password,
		DB: app.config.Redis.DB,
		PoolSize: app.config.Redis.PoolSize,
		MinIdleConns: app.config.Redis.MinIdleConns,
		DialTimeout: app.config.Redis.DialTimeout,
		ReadTimeout: app.config.Redis.ReadTimeout,
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

func (app *Application) initDomainServices() error {
	var err error
	redisClient, ok := app.redisClient.GetClient().(*redis.Client)
    if !ok {
        return fmt.Errorf("unexpected redis client type: %T", app.redisClient.GetClient())
    }

	vaultProvider, err := kms.NewVaultProvider(app.config.Vault, app.vaultClient, app.logger)
	if err != nil {
		return fmt.Errorf("failed to create vault provider: %w", err)
	}

	keyProviders := map[string]domainService.KeyProvider{
		"vault": vaultProvider,
	}

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
	app.policyService = policy.NewStubPolicyService()
	app.mgrKeyFetcher = kms.NewMgrKeyFetcher(app.vaultClient, redisClient)

	app.logger.Info(app.ctx, "Domain services initialized via adapters")
	return nil
}

func (app *Application) initMonitoring() error {
	app.metrics = monitoring.NewMetrics(prometheus.DefaultRegisterer)
	// Initialize tracer
	_, err := monitoring.NewTracingManager(app.config, app.logger)
	if err != nil {
		return fmt.Errorf("failed to create tracing manager: %w", err)
	}
	app.logger.Info(app.ctx, "Monitoring components initialized")
	return nil
}

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

func (app *Application) initApplicationServices() error {
	tokenDomainService := domainService.NewTokenDomainService(app.tokenRepo, app.kms, app.logger)

	redisClient, ok := app.redisClient.GetClient().(*redis.Client)
	if !ok {
		return fmt.Errorf("unexpected redis client type: %T", app.redisClient.GetClient())
	}
	deviceAuthStore := redisStore.NewRedisDeviceAuthStore(redisClient)

	app.authAppService = service.NewAuthAppService(tokenDomainService, app.deviceRepo, app.tenantRepo, app.rateLimitService, app.blacklistStore, app.auditService, app.logger)
	app.deviceAuthAppService = service.NewDeviceAuthAppService(deviceAuthStore, tokenDomainService, app.kms, &app.config.OAuth)
	app.deviceAppService = service.NewDeviceAppService(app.deviceRepo, app.auditService, app.mgrKeyFetcher, app.policyService, tokenDomainService, app.config, app.logger)
	app.tenantAppService = service.NewTenantAppService(app.tenantRepo, app.kms, app.cdnManager, app.logger)
	app.logger.Info(app.ctx, "Application services initialized")
	return nil
}

func (app *Application) initInterfaces() error {
	tlsConfig, err := app.setupTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to setup TLS config: %w", err)
	}

	// HTTP Server
	httpPort := fmt.Sprintf(":%d", app.config.Server.HTTPPort)
	if app.config.Server.HTTPPort == 0 {
		httpPort = ":" + DefaultHTTPPort
	}
	metricsAdapter := handlers.NewMetricsAdapter(app.metrics)
	authHandler := handlers.NewAuthHandler(app.authAppService, app.deviceAuthAppService, metricsAdapter, app.logger)
	oauthHandler := handlers.NewOAuthHandler(app.deviceAuthAppService)
	deviceHandler := handlers.NewDeviceHandler(app.deviceAppService, metricsAdapter, app.logger)
	healthHandler := handlers.NewHealthHandler(app.dbConn, app.redisClient, app.logger)
	jwksHandler := handlers.NewJWKSHandler(app.kms, app.logger, metricsAdapter)

	// Middleware
	authMiddleware := middleware.RequireJWT(app.kms, app.blacklistStore, app.logger)
	rateLimitMiddleware := middleware.RateLimitMiddleware(app.rateLimitService, &app.config.RateLimit, app.logger)
	idempotencyMiddleware := middleware.IdempotencyMiddleware(app.redisClient.GetClient(), &app.config.Idempotency, app.logger)
	observabilityMiddleware := middleware.ObservabilityMiddleware(otel.Tracer(ServiceName), app.metrics.HTTPRequestsTotal, app.metrics.HTTPRequestDuration)

	router := httpRouter.NewRouter(app.config, app.logger, healthHandler, authHandler, deviceHandler, jwksHandler, oauthHandler, authMiddleware, rateLimitMiddleware, idempotencyMiddleware, observabilityMiddleware)
	router.SetupRoutes()
	app.httpServer = &http.Server{Addr: httpPort, Handler: router.Engine(), TLSConfig: tlsConfig}
	app.logger.Info(app.ctx, "HTTP interface initialized", logger.String("port", httpPort))

	// Internal HTTP Server for ML Risk Updates
	internalHTTPPort := fmt.Sprintf(":%d", app.config.Server.InternalHTTPPort)
	riskUpdateService := application.NewRiskUpdateService(app.riskRepo)
	mlInternalHandler := handlers.NewMLInternalHandler(riskUpdateService)
	internalRouter := httpRouter.NewInternalRouter(mlInternalHandler)
	internalRouter.SetupRoutes()
	app.internalHTTPServer = &http.Server{Addr: internalHTTPPort, Handler: internalRouter.Engine()}
	app.logger.Info(app.ctx, "Internal HTTP interface initialized", logger.String("port", internalHTTPPort))

	// gRPC Server
	grpcPort := fmt.Sprintf(":%d", app.config.Server.GRPCPort)
	if app.config.Server.GRPCPort == 0 {
		grpcPort = ":" + DefaultGRPCPort
	}
	listener, err := net.Listen("tcp", grpcPort)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port: %w", err)
	}
	var opts []grpc.ServerOption
	if tlsConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}
	app.grpcServer = grpc.NewServer(opts...)
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

func (app *Application) setupTLSConfig() (*tls.Config, error) {
	if !app.config.Server.TLS.Enabled {
		return nil, nil
	}

	serverCert, err := tls.LoadX509KeyPair(app.config.Server.TLS.CertFile, app.config.Server.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	if app.config.Server.TLS.ClientCAFile != "" {
		caCert, err := os.ReadFile(app.config.Server.TLS.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to add client CA's certificate")
		}
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		app.logger.Info(app.ctx, "mTLS enabled")
	}

	return tlsConfig, nil
}

func (app *Application) Start() error {
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

	go func() {
		app.logger.Info(app.ctx, "Starting internal HTTP server")
		if err := app.internalHTTPServer.ListenAndServe(); err != http.ErrServerClosed {
			app.logger.Fatal(app.ctx, "Internal HTTP server crashed", err)
		}
	}()

	go func() {
		mux := http.NewServeMux()
		mux.Handle(app.config.Observability.MetricsEndpoint, promhttp.Handler())
		if err := http.ListenAndServe(fmt.Sprintf(":%d", app.config.Observability.PrometheusPort), mux); err != http.ErrServerClosed {
			app.logger.Error(app.ctx, "Metrics server crashed", err)
		}
	}()
	app.logger.Info(app.ctx, "All services started")
	return nil
}

func (app *Application) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	app.logger.Info(app.ctx, "Shutdown signal received")
}

func (app *Application) Shutdown() error {
	app.logger.Info(app.ctx, "Shutting down application...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()

	if err := app.httpServer.Shutdown(shutdownCtx); err != nil {
		app.logger.Error(shutdownCtx, "HTTP server shutdown error", err)
	}
	if err := app.internalHTTPServer.Shutdown(shutdownCtx); err != nil {
		app.logger.Error(shutdownCtx, "Internal HTTP server shutdown error", err)
	}
	app.grpcServer.GracefulStop()

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
