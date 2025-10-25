package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

type tokenRepositoryImpl struct {
	db  *DBConnection
	log logger.Logger
}

// NewTokenRepository creates a new PostgreSQL-backed TokenRepository.
func NewTokenRepository(db *DBConnection, log logger.Logger) repository.TokenRepository {
	return &tokenRepositoryImpl{db: db, log: log}
}

// Save persists a new token to the database.
func (r *tokenRepositoryImpl) Save(ctx context.Context, token *models.Token) *errors.AppError {
	query := `
		INSERT INTO tokens (id, jti, tenant_id, device_id, token_type, issued_at, expires_at, scope, audience, issuer)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := r.db.Pool.Exec(ctx, query,
		token.ID, token.JTI, token.TenantID, token.DeviceID,
		token.TokenType, token.IssuedAt, token.ExpiresAt,
		token.Scope, token.Audience, token.Issuer,
	)

	if err != nil {
		r.log.Error(ctx, "Failed to save token", err)
		return errors.ErrDatabase.WithError(err)
	}
	return nil
}

// FindByJTI retrieves a token by its JTI.
func (r *tokenRepositoryImpl) FindByJTI(ctx context.Context, jti string) (*models.Token, *errors.AppError) {
	query := `
		SELECT id, jti, tenant_id, device_id, token_type, issued_at, expires_at, revoked_at, scope, audience, issuer
		FROM tokens WHERE jti = $1
	`
	row := r.db.Pool.QueryRow(ctx, query, jti)
	return r.scanToken(ctx, row)
}

// FindByDeviceID retrieves the latest token for a specific device.
func (r *tokenRepositoryImpl) FindByDeviceID(ctx context.Context, deviceID uuid.UUID, tokenType string) (*models.Token, *errors.AppError) {
	query := `
		SELECT id, jti, tenant_id, device_id, token_type, issued_at, expires_at, revoked_at, scope, audience, issuer
		FROM tokens WHERE device_id = $1 AND token_type = $2
		ORDER BY issued_at DESC LIMIT 1
	`
	row := r.db.Pool.QueryRow(ctx, query, deviceID, tokenType)
	return r.scanToken(ctx, row)
}

// Revoke marks a token as revoked.
func (r *tokenRepositoryImpl) Revoke(ctx context.Context, jti string, revokedAt time.Time) *errors.AppError {
	query := `UPDATE tokens SET revoked_at = $1 WHERE jti = $2`
	cmdTag, err := r.db.Pool.Exec(ctx, query, revokedAt, jti)
	if err != nil {
		r.log.Error(ctx, "Failed to revoke token", err)
		return errors.ErrDatabase.WithError(err)
	}
	if cmdTag.RowsAffected() == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// DeleteExpired removes expired tokens from the database.
func (r *tokenRepositoryImpl) DeleteExpired(ctx context.Context) (int64, *errors.AppError) {
	query := `DELETE FROM tokens WHERE expires_at < NOW()`
	cmdTag, err := r.db.Pool.Exec(ctx, query)
	if err != nil {
		r.log.Error(ctx, "Failed to delete expired tokens", err)
		return 0, errors.ErrDatabase.WithError(err)
	}
	return cmdTag.RowsAffected(), nil
}

func (r *tokenRepositoryImpl) scanToken(ctx context.Context, row pgx.Row) (*models.Token, *errors.AppError) {
	var token models.Token
	err := row.Scan(
		&token.ID, &token.JTI, &token.TenantID, &token.DeviceID, &token.TokenType,
		&token.IssuedAt, &token.ExpiresAt, &token.RevokedAt,
		&token.Scope, &token.Audience, &token.Issuer,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		r.log.Error(ctx, "Failed to scan token row", err)
		return nil, errors.ErrDatabase.WithError(err)
	}
	return &token, nil
}

//Personal.AI order the ending
