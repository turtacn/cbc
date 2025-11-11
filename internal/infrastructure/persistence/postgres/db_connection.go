// Package postgres provides PostgreSQL database connection management for cbc-auth-service.
// It implements connection pooling, health checks, and lifecycle management using pgx driver.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DBConnection manages the lifecycle of the PostgreSQL database connection pool.
// It provides a thread-safe connection pool with automatic health monitoring and integrates both `pgxpool` for performance and `gorm` for ORM capabilities.
// DBConnection 管理 PostgreSQL 数据库连接池的生命周期。
// 它提供了一个线程安全的连接池，具有自动健康监控功能，并集成了用于性能的 `pgxpool` 和用于 ORM 功能的 `gorm`。
type DBConnection struct {
	pool   *pgxpool.Pool
	gormDB *gorm.DB
	config *config.DatabaseConfig
	logger logger.Logger
}

// NewDBConnection creates and initializes a new PostgreSQL connection manager.
// It sets up the connection pool based on the provided configuration, establishes the connection,
// and performs an initial health check to ensure the database is reachable.
// NewDBConnection 创建并初始化一个新的 PostgreSQL 连接管理器。
// 它根据提供的配置设置连接池，建立连接，并执行初始健康检查以确保数据库是可达的。
//
// Parameters:
//   - ctx: A context.Context for controlling timeouts during the initial connection.
//   - cfg: The database configuration, including credentials, host, and pool settings.
//   - log: A logger instance for recording connection lifecycle events.
//
// Returns:
//   - *DBConnection: A pointer to the initialized DBConnection manager.
//   - error: An error if the connection cannot be established or the initial ping fails.
func NewDBConnection(ctx context.Context, cfg *config.DatabaseConfig, log logger.Logger) (*DBConnection, error) {
	if cfg == nil {
		return nil, errors.New(errors.CodeInvalidArgument, "database config is required")
	}

	log.Info(ctx, "Initializing PostgreSQL connection pool",
		logger.String("host", cfg.Host),
		logger.Int("port", int(cfg.Port)),
		logger.String("database", cfg.Database),
		logger.Int("max_conns", int(cfg.MaxConns)),
		logger.Int("min_conns", int(cfg.MinConns)),
	)

	// Construct PostgreSQL connection string
	connString := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host,
		cfg.Port,
		cfg.User,
		cfg.Password,
		cfg.Database,
		cfg.SSLMode,
	)

	// Parse connection configuration
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		log.Error(ctx, "Failed to parse database connection string", err)
		return nil, errors.New(errors.CodeInternal, "failed to parse database connection string")
	}

	// Configure connection pool parameters
	poolConfig.MaxConns = int32(cfg.MaxConns)
	poolConfig.MinConns = int32(cfg.MinConns)
	poolConfig.MaxConnLifetime = time.Duration(cfg.MaxConnLifetime) * time.Second
	poolConfig.MaxConnIdleTime = time.Duration(cfg.MaxConnIdleTime) * time.Second
	poolConfig.HealthCheckPeriod = time.Duration(cfg.HealthCheckPeriod) * time.Second

	// Set connection timeout
	connectCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.ConnTimeout)*time.Second)
	defer cancel()

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(connectCtx, poolConfig)
	if err != nil {
		log.Error(ctx, "Failed to create database connection pool", err)
		return nil, errors.New(errors.CodeInternal, "failed to create database connection pool")
	}

	// Create GORM connection
	gormDB, err := gorm.Open(postgres.Open(connString), &gorm.Config{})
	if err != nil {
		log.Error(ctx, "Failed to create GORM database connection", err)
		pool.Close()
		return nil, errors.New(errors.CodeInternal, "failed to create GORM database connection")
	}

	dbConn := &DBConnection{
		pool:   pool,
		gormDB: gormDB,
		config: cfg,
		logger: log,
	}

	// Perform initial health check
	if err := dbConn.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	log.Info(ctx, "PostgreSQL connection pool initialized successfully",
		logger.Int("total_conns", int(pool.Stat().TotalConns())),
		logger.Int("idle_conns", int(pool.Stat().IdleConns())),
	)

	return dbConn, nil
}

// Pool returns the underlying `pgxpool.Pool` for executing efficient, low-level database operations.
// This is the preferred method for repositories that need high performance.
// Pool 返回底层的 `pgxpool.Pool`，用于执行高效的、低级别的数据库操作。
// 这是需要高性能的仓库的首选方法。
//
// Returns:
//   - *pgxpool.Pool: The active connection pool instance.
func (db *DBConnection) Pool() *pgxpool.Pool {
	return db.pool
}

// DB returns the underlying `gorm.DB` instance for ORM-based database operations.
// This is useful for complex queries or when leveraging GORM's features.
// DB 返回底层的 `gorm.DB` 实例，用于基于 ORM 的数据库操作。
// 这对于复杂的查询或利用 GORM 的功能很有用。
//
// Returns:
//   - *gorm.DB: The active GORM database handle.
func (db *DBConnection) DB() *gorm.DB {
	return db.gormDB
}

// Ping verifies the connectivity and responsiveness of the database.
// It executes a simple query and also checks for high latency, logging a warning if it exceeds a threshold.
// Ping 验证数据库的连接性和响应能力。
// 它执行一个简单的查询，并检查高延迟，如果超过阈值则记录警告。
//
// Parameters:
//   - ctx: A context.Context for controlling the timeout of the ping operation.
//
// Returns:
//   - error: An error if the database is unreachable or unresponsive.
func (db *DBConnection) Ping(ctx context.Context) error {
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	startTime := time.Now()
	if err := db.pool.Ping(pingCtx); err != nil {
		db.logger.Error(ctx, "Database ping failed", err)
		return errors.New(errors.CodeInternal, "database ping failed")
	}

	latency := time.Since(startTime)
	db.logger.Debug(ctx, "Database ping successful", logger.Int64("latency_ms", latency.Milliseconds()))

	// Warn if latency is high (> 100ms)
	if latency > 100*time.Millisecond {
		db.logger.Warn(ctx, "High database latency detected",
			logger.Int64("latency_ms", latency.Milliseconds()),
			logger.Int("threshold_ms", 100),
		)
	}

	return nil
}

// HealthCheck performs a comprehensive health check of the database connection pool.
// It returns detailed statistics about the pool's state, such as total, idle, and acquired connections.
// It also includes a warning if the pool is nearing its configured limit.
// HealthCheck 对数据库连接池执行全面的健康检查。
// 它返回有关池状态的详细统计信息，例如总连接数、空闲连接数和已获取的连接数。
// 如果池接近其配置的限制，它还会包含一个警告。
//
// Parameters:
//   - ctx: A context.Context for controlling the timeout of the health check.
//
// Returns:
//   - map[string]interface{}: A map containing health metrics and pool statistics.
//   - error: An error if the underlying ping check fails.
func (db *DBConnection) HealthCheck(ctx context.Context) (map[string]interface{}, error) {
	if err := db.Ping(ctx); err != nil {
		return nil, err
	}

	stats := db.pool.Stat()
	healthInfo := map[string]interface{}{
		"status":                 "healthy",
		"total_connections":      stats.TotalConns(),
		"idle_connections":       stats.IdleConns(),
		"acquired_connections":   stats.AcquiredConns(),
		"constructing_conns":     stats.ConstructingConns(),
		"max_connections":        db.config.MaxConns,
		"acquire_count":          stats.AcquireCount(),
		"acquire_duration_ms":    stats.AcquireDuration().Milliseconds(),
		"empty_acquire_count":    stats.EmptyAcquireCount(),
		"canceled_acquire_count": stats.CanceledAcquireCount(),
	}

	// Check for potential issues
	if stats.IdleConns() == 0 && stats.TotalConns() >= int32(db.config.MaxConns) {
		db.logger.Warn(ctx, "Connection pool exhausted",
			logger.Int32("total_conns", stats.TotalConns()),
			logger.Int32("max_conns", db.config.MaxConns),
		)
		healthInfo["warning"] = "connection_pool_near_limit"
	}

	return healthInfo, nil
}

// Close gracefully shuts down the database connection pool.
// It should be called during application termination to ensure all connections are properly closed.
// Close 优雅地关闭数据库连接池。
// 应在应用程序终止期间调用此方法，以确保所有连接都已正确关闭。
func (db *DBConnection) Close() {
	db.logger.Info(context.Background(), "Closing PostgreSQL connection pool",
		logger.Int("total_conns", int(db.pool.Stat().TotalConns())),
		logger.Int("acquired_conns", int(db.pool.Stat().AcquiredConns())),
	)

	db.pool.Close()

	db.logger.Info(context.Background(), "PostgreSQL connection pool closed successfully")
}

// Stats returns a snapshot of the current connection pool statistics.
// This is useful for monitoring, alerting, and debugging connection pool behavior.
// Stats 返回当前连接池统计信息的快照。
// 这对于监控、警报和调试连接池行为非常有用。
//
// Returns:
//   - *pgxpool.Stat: A snapshot of the pool's statistics.
func (db *DBConnection) Stats() *pgxpool.Stat {
	stats := db.pool.Stat()
	return stats
}

// Config returns the database configuration that the connection is currently using.
// This is useful for debugging and runtime validation.
// Config 返回连接当前正在使用的数据库配置。
// 这对于调试和运行时验证非常有用。
//
// Returns:
//   - *config.DatabaseConfig: The current database configuration.
func (db *DBConnection) Config() *config.DatabaseConfig {
	return db.config
}
