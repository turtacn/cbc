package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/internal/infrastructure/ratelimit"
	"github.com/turtacn/cbc/internal/interfaces/grpc"
	"github.com/turtacn/cbc/internal/interfaces/http"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/pkg/logger"
	"google.golang.org/grpc"
)

func main() {
	// Logger for startup
	startupLogger, _ := monitoring.NewZapLogger(&config.LogConfig{Level: "info"})

	// Load config
	cfg, err := config.LoadConfig(startupLogger)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize logger
	appLogger, err := monitoring.NewZapLogger(&cfg.Log)
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}

	// Initialize tracing
	cleanup, err := monitoring.InitTracer(&cfg.Tracing)
	if err != nil {
		appLogger.Fatal(context.Background(), "Failed to initialize tracer", err)
	}
	defer cleanup()

	// Initialize database
	db, err := postgres.NewDBConnection(&cfg.Database, appLogger)
	if err != nil {
		appLogger.Fatal(context.Background(), "Failed to connect to database", err)
	}
	defer db.Close()

	// Initialize Redis
	redisConn, err := redis.NewRedisConnection(&cfg.Redis, appLogger)
	if err != nil {
		appLogger.Fatal(context.Background(), "Failed to connect to Redis", err)
	}
	defer redisConn.Close()

	// Initialize Vault
	vaultClient, err := crypto.NewVaultClient(&cfg.Vault, appLogger)
	if err != nil {
		appLogger.Fatal(context.Background(), "Failed to create Vault client", err)
	}

	// Initialize infrastructure
	metrics := monitoring.NewMetrics()
	cacheManager := redis.NewCacheManager(redisConn, appLogger)
	keyManager := crypto.NewKeyManager(vaultClient, cacheManager, appLogger)
	jwtManager := crypto.NewJWTManager(keyManager, appLogger)
	rateLimiter := ratelimit.NewRedisRateLimiter(redisConn, appLogger)

	// Initialize repositories
	tokenRepo := postgres.NewTokenRepository(db, appLogger)
	deviceRepo := postgres.NewDeviceRepository(db, appLogger)
	tenantRepo := postgres.NewTenantRepository(db, appLogger)

	// Initialize application services
	authAppSvc := service.NewAuthAppService(jwtManager, deviceRepo, tenantRepo, rateLimiter, appLogger)
	deviceAppSvc := service.NewDeviceAppService(deviceRepo, appLogger)

	// Initialize HTTP handlers and router
	authHandler := handlers.NewAuthHandler(authAppSvc, metrics)
	deviceHandler := handlers.NewDeviceHandler(deviceAppSvc)
	healthHandler := handlers.NewHealthHandler(db, redisConn, vaultClient, appLogger)

	http.StartServer(
		http.NewRouter(http.RouterDependencies{
			Config: &cfg.Server,
			Logger: appLogger,
			AuthHandler: authHandler,
			DeviceHandler: deviceHandler,
			HealthHandler: healthHandler,
			Middleware: []gin.HandlerFunc{
				handlers.RecoveryMiddleware(appLogger),
				handlers.TracingMiddleware(),
				handlers.LoggingMiddleware(appLogger),
				handlers.CORSMiddleware(),
			},
		}),
		&cfg.Server, appLogger,
	)

	// Initialize and start gRPC server
	startGRPCServer(cfg, authAppSvc, jwtManager, appLogger)
}

func startGRPCServer(cfg *config.Config, authAppSvc service.AuthAppService, cryptoSvc service.CryptoService, log logger.Logger) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
	if err != nil {
		log.Fatal(context.Background(), "Failed to listen for gRPC", err)
	}

	grpcServer := grpc.NewAuthGRPCServer(
		authAppSvc, cryptoSvc, log,
		[]grpc.UnaryServerInterceptor{
			grpc.UnaryRecoveryInterceptor(log),
			grpc.UnaryLoggingInterceptor(log),
		},
	)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatal(context.Background(), "gRPC server failed", err)
		}
	}()

	log.Info(context.Background(), fmt.Sprintf("gRPC server listening on :%d", cfg.Server.GRPCPort))
}
//Personal.AI order the ending