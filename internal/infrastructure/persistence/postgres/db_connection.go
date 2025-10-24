package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// DBConnection manages the PostgreSQL connection pool.
type DBConnection struct {
	Pool *pgxpool.Pool
	log  logger.Logger
}

// NewDBConnection creates a new PostgreSQL connection pool.
func NewDBConnection(cfg *config.DatabaseConfig, log logger.Logger) (*DBConnection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	poolConfig, err := pgxpool.ParseConfig(cfg.GetDSN())
	if err != nil {
		return nil, err
	}

	poolConfig.MaxConns = int32(cfg.MaxConns)
	poolConfig.MinConns = int32(cfg.MinConns)
	poolConfig.MaxConnLifetime = time.Duration(cfg.MaxConnLifetime) * time.Minute
	poolConfig.MaxConnIdleTime = time.Duration(cfg.MaxConnIdleTime) * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, err
	}

	if err = pool.Ping(ctx); err != nil {
		return nil, err
	}

	log.Info(ctx, "PostgreSQL connection pool created successfully")
	return &DBConnection{Pool: pool, log: log}, nil
}

// Ping checks the health of the database connection.
func (db *DBConnection) Ping(ctx context.Context) *errors.AppError {
	if err := db.Pool.Ping(ctx); err != nil {
		return errors.ErrDatabase.WithError(err)
	}
	return nil
}

// Close gracefully closes the database connection pool.
func (db *DBConnection) Close() {
	db.log.Info(context.Background(), "Closing PostgreSQL connection pool")
	db.Pool.Close()
}
//Personal.AI order the ending