// Package postgres implements PostgreSQL-based repository for token management.
// It provides persistent storage for JWT token metadata with transaction support.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// TokenRepositoryImpl implements TokenRepository interface using PostgreSQL.
// It provides ACID-compliant token metadata storage with optimized queries.
type TokenRepositoryImpl struct {
	db     *DBConnection
	logger logger.Logger
}

// NewTokenRepository creates a new PostgreSQL token repository instance.
//
// Parameters:
//   - db: Database connection manager
//   - log: Logger instance for repository operations
//
// Returns:
//   - repository.TokenRepository: Initialized repository implementation
func NewTokenRepository(db *DBConnection, log logger.Logger) repository.TokenRepository {
	return &TokenRepositoryImpl{
		db:     db,
		logger: log,
	}
}

// Save persists a new token metadata to database.
// It uses INSERT ... ON CONFLICT to handle duplicate JTI scenarios gracefully.
//
// Parameters:
//   - ctx: Context for timeout and cancellation
//   - token: Token model containing metadata to persist
//
// Returns:
//   - error: Persistence error including constraint violations
func (r *TokenRepositoryImpl) Save(ctx context.Context, token *models.Token) error {
	query := `
		INSERT INTO token_metadata (
			jti, tenant_id, agent_id, token_type, scope,
			issued_at, expires_at, revoked_at, device_fingerprint,
			ip_address, user_agent, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW()
		)
		ON CONFLICT (jti) DO UPDATE SET
			revoked_at = EXCLUDED.revoked_at,
			updated_at = NOW()
		RETURNING id, created_at
	`

	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		if latency > 100*time.Millisecond {
			r.logger.Warn("Slow token save query detected",
				"latency_ms", latency.Milliseconds(),
				"jti", token.JTI,
			)
		}
	}()

	var id int64
	var createdAt time.Time
	err := r.db.Pool().QueryRow(ctx, query,
		token.JTI,
		token.TenantID,
		token.AgentID,
		token.TokenType,
		token.Scope,
		token.IssuedAt,
		token.ExpiresAt,
		token.RevokedAt,
		token.DeviceFingerprint,
		token.IPAddress,
		token.UserAgent,
	).Scan(&id, &createdAt)

	if err != nil {
		r.logger.Error("Failed to save token metadata",
			"jti", token.JTI,
			"tenant_id", token.TenantID,
			"error", err,
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	token.ID = id
	token.CreatedAt = createdAt

	r.logger.Info("Token metadata saved successfully",
		"jti", token.JTI,
		"tenant_id", token.TenantID,
		"token_type", token.TokenType,
		"expires_at", token.ExpiresAt,
	)

	return nil
}

// FindByJTI retrieves token metadata by JWT ID.
// It uses prepared statement for optimal query performance.
//
// Parameters:
//   - ctx: Context for timeout control
//   - jti: JWT unique identifier
//
// Returns:
//   - *models.Token: Token metadata if found
//   - error: ErrTokenNotFound if token doesn't exist, or database error
func (r *TokenRepositoryImpl) FindByJTI(ctx context.Context, jti string) (*models.Token, error) {
	query := `
		SELECT 
			id, jti, tenant_id, agent_id, token_type, scope,
			issued_at, expires_at, revoked_at, device_fingerprint,
			ip_address, user_agent, created_at, updated_at
		FROM token_metadata
		WHERE jti = $1
	`

	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		if latency > 50*time.Millisecond {
			r.logger.Warn("Slow token find query detected",
				"latency_ms", latency.Milliseconds(),
				"jti", jti,
			)
		}
	}()

	token := &models.Token{}
	var revokedAt sql.NullTime
	var updatedAt sql.NullTime

	err := r.db.Pool().QueryRow(ctx, query, jti).Scan(
		&token.ID,
		&token.JTI,
		&token.TenantID,
		&token.AgentID,
		&token.TokenType,
		&token.Scope,
		&token.IssuedAt,
		&token.ExpiresAt,
		&revokedAt,
		&token.DeviceFingerprint,
		&token.IPAddress,
		&token.UserAgent,
		&token.CreatedAt,
		&updatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Debug("Token not found", "jti", jti)
			return nil, errors.ErrTokenNotFound
		}
		r.logger.Error("Failed to find token by JTI", "jti", jti, "error", err)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}
	if updatedAt.Valid {
		token.UpdatedAt = &updatedAt.Time
	}

	return token, nil
}

// FindByAgentID retrieves all tokens for a specific agent with pagination.
//
// Parameters:
//   - ctx: Context for timeout control
//   - agentID: Agent identifier
//   - limit: Maximum number of records to return
//   - offset: Number of records to skip
//
// Returns:
//   - []*models.Token: List of token metadata
//   - error: Database operation error if any
func (r *TokenRepositoryImpl) FindByAgentID(ctx context.Context, agentID string, limit, offset int) ([]*models.Token, error) {
	query := `
		SELECT 
			id, jti, tenant_id, agent_id, token_type, scope,
			issued_at, expires_at, revoked_at, device_fingerprint,
			ip_address, user_agent, created_at, updated_at
		FROM token_metadata
		WHERE agent_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.Pool().Query(ctx, query, agentID, limit, offset)
	if err != nil {
		r.logger.Error("Failed to query tokens by agent ID", "agent_id", agentID, "error", err)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}
	defer rows.Close()

	var tokens []*models.Token
	for rows.Next() {
		token := &models.Token{}
		var revokedAt sql.NullTime
		var updatedAt sql.NullTime

		err := rows.Scan(
			&token.ID,
			&token.JTI,
			&token.TenantID,
			&token.AgentID,
			&token.TokenType,
			&token.Scope,
			&token.IssuedAt,
			&token.ExpiresAt,
			&revokedAt,
			&token.DeviceFingerprint,
			&token.IPAddress,
			&token.UserAgent,
			&token.CreatedAt,
			&updatedAt,
		)
		if err != nil {
			r.logger.Error("Failed to scan token row", "error", err)
			return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
		}

		if revokedAt.Valid {
			token.RevokedAt = &revokedAt.Time
		}
		if updatedAt.Valid {
			token.UpdatedAt = &updatedAt.Time
		}

		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		r.logger.Error("Error iterating token rows", "error", err)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	return tokens, nil
}

// Revoke marks a token as revoked using optimistic locking.
// It updates revoked_at timestamp only if the token hasn't been revoked yet.
//
// Parameters:
//   - ctx: Context for timeout control
//   - jti: JWT unique identifier to revoke
//
// Returns:
//   - error: ErrTokenNotFound if token doesn't exist, ErrTokenAlreadyRevoked if already revoked
func (r *TokenRepositoryImpl) Revoke(ctx context.Context, jti string) error {
	query := `
		UPDATE token_metadata
		SET revoked_at = NOW(), updated_at = NOW()
		WHERE jti = $1 AND revoked_at IS NULL
		RETURNING id, revoked_at
	`

	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		if latency > 100*time.Millisecond {
			r.logger.Warn("Slow token revoke query detected",
				"latency_ms", latency.Milliseconds(),
				"jti", jti,
			)
		}
	}()

	var id int64
	var revokedAt time.Time
	err := r.db.Pool().QueryRow(ctx, query, jti).Scan(&id, &revokedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			// Check if token exists but already revoked
			existingToken, findErr := r.FindByJTI(ctx, jti)
			if findErr != nil {
				r.logger.Debug("Token not found for revocation", "jti", jti)
				return errors.ErrTokenNotFound
			}
			if existingToken.RevokedAt != nil {
				r.logger.Debug("Token already revoked", "jti", jti, "revoked_at", existingToken.RevokedAt)
				return errors.ErrTokenAlreadyRevoked
			}
		}
		r.logger.Error("Failed to revoke token", "jti", jti, "error", err)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	r.logger.Info("Token revoked successfully",
		"jti", jti,
		"revoked_at", revokedAt,
	)

	return nil
}

// IsRevoked checks if a token has been revoked.
// This is optimized for high-frequency validation operations.
//
// Parameters:
//   - ctx: Context for timeout control
//   - jti: JWT unique identifier
//
// Returns:
//   - bool: true if token is revoked
//   - error: Database operation error if any
func (r *TokenRepositoryImpl) IsRevoked(ctx context.Context, jti string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM token_metadata
			WHERE jti = $1 AND revoked_at IS NOT NULL
		)
	`

	var isRevoked bool
	err := r.db.Pool().QueryRow(ctx, query, jti).Scan(&isRevoked)
	if err != nil {
		r.logger.Error("Failed to check token revocation status", "jti", jti, "error", err)
		return false, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	return isRevoked, nil
}

// DeleteExpired removes all expired tokens from database.
// It performs batch deletion with transaction support to maintain consistency.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - int64: Number of tokens deleted
//   - error: Database operation error if any
func (r *TokenRepositoryImpl) DeleteExpired(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM token_metadata
		WHERE expires_at < NOW()
	`

	startTime := time.Now()
	result, err := r.db.Pool().Exec(ctx, query)
	if err != nil {
		r.logger.Error("Failed to delete expired tokens", "error", err)
		return 0, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	rowsAffected := result.RowsAffected()
	latency := time.Since(startTime)

	r.logger.Info("Expired tokens deleted successfully",
		"rows_deleted", rowsAffected,
		"latency_ms", latency.Milliseconds(),
	)

	return rowsAffected, nil
}

// CountByTenantID counts total tokens for a specific tenant.
// Useful for analytics and monitoring.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//
// Returns:
//   - int64: Total token count
//   - error: Database operation error if any
func (r *TokenRepositoryImpl) CountByTenantID(ctx context.Context, tenantID string) (int64, error) {
	query := `
		SELECT COUNT(*) FROM token_metadata WHERE tenant_id = $1
	`

	var count int64
	err := r.db.Pool().QueryRow(ctx, query, tenantID).Scan(&count)
	if err != nil {
		r.logger.Error("Failed to count tokens", "tenant_id", tenantID, "error", err)
		return 0, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}

	return count, nil
}

// BeginTx starts a new database transaction.
// Useful for atomic multi-operation scenarios.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - pgx.Tx: Transaction handle
//   - error: Transaction start error if any
func (r *TokenRepositoryImpl) BeginTx(ctx context.Context) (pgx.Tx, error) {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		r.logger.Error("Failed to begin transaction", "error", err)
		return nil, fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, err)
	}
	return tx, nil
}

//Personal.AI order the ending
