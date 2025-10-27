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
)

// DBConnection manages PostgreSQL database connection pool lifecycle.
// It provides thread-safe connection pool with automatic health monitoring.
type DBConnection struct {
	pool   *pgxpool.Pool
	config *config.DatabaseConfig
	logger logger.Logger
}

// NewDBConnection creates a new PostgreSQL connection manager instance.
// It initializes connection pool with configuration parameters and performs initial health check.
//
// Parameters:
//   - ctx: Context for connection timeout control
//   - cfg: Database configuration including host, port, credentials, and pool settings
//   - log: Logger instance for connection lifecycle events
//
// Returns:
//   - *DBConnection: Initialized connection manager
//   - error: Connection establishment error if any
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

	dbConn := &DBConnection{
		pool:   pool,
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

// Pool returns the underlying pgxpool.Pool for executing database operations.
// This method is primarily used by repository implementations.
//
// Returns:
//   - *pgxpool.Pool: Active connection pool instance
func (db *DBConnection) Pool() *pgxpool.Pool {
	return db.pool
}

// Ping verifies database connectivity and responsiveness.
// It executes a simple query to ensure the connection is alive.
//
// Parameters:
//   - ctx: Context for timeout control (recommended: 5-10 seconds)
//
// Returns:
//   - error: Connection error if database is unreachable or unresponsive
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

// HealthCheck performs comprehensive health check including connection stats.
// It returns detailed information about connection pool status.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - map[string]interface{}: Health metrics including pool statistics
//   - error: Health check error if any
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

// Close gracefully shuts down the connection pool.
// It waits for active connections to complete before closing.
// This method should be called during application shutdown.
func (db *DBConnection) Close() {
	db.logger.Info(context.Background(), "Closing PostgreSQL connection pool",
		logger.Int("total_conns", int(db.pool.Stat().TotalConns())),
		logger.Int("acquired_conns", int(db.pool.Stat().AcquiredConns())),
	)

	db.pool.Close()

	db.logger.Info(context.Background(), "PostgreSQL connection pool closed successfully")
}

// Stats returns current connection pool statistics.
// Useful for monitoring and alerting.
//
// Returns:
//   - *pgxpool.Stat: Pool statistics snapshot
func (db *DBConnection) Stats() *pgxpool.Stat {
	stats := db.pool.Stat()
	return stats
}

// Config returns the database configuration.
// This is useful for debugging and validation purposes.
//
// Returns:
//   - *config.DatabaseConfig: Current database configuration
func (db *DBConnection) Config() *config.DatabaseConfig {
	return db.config
}

//Personal.AI order the ending
