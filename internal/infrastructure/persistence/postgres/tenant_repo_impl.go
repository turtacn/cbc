package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

type tenantRepositoryImpl struct {
	db  *DBConnection
	log logger.Logger
}

// NewTenantRepository creates a new PostgreSQL-backed TenantRepository.
func NewTenantRepository(db *DBConnection, log logger.Logger) repository.TenantRepository {
	return &tenantRepositoryImpl{db: db, log: log}
}

// Save persists a new tenant.
func (r *tenantRepositoryImpl) Save(ctx context.Context, tenant *models.Tenant) *errors.AppError {
	query := `
		INSERT INTO tenants (id, tenant_name, status, access_token_ttl, refresh_token_ttl, key_rotation_policy, rate_limit_config)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.Pool.Exec(ctx, query,
		tenant.ID, tenant.TenantName, tenant.Status, tenant.AccessTokenTTL,
		tenant.RefreshTokenTTL, tenant.KeyRotationPolicy, tenant.RateLimitConfig,
	)
	if err != nil {
		r.log.Error(ctx, "Failed to save tenant", err)
		return errors.ErrDatabase.WithError(err)
	}
	return nil
}

// FindByID retrieves a tenant by its UUID.
func (r *tenantRepositoryImpl) FindByID(ctx context.Context, id uuid.UUID) (*models.Tenant, *errors.AppError) {
	query := `
		SELECT id, tenant_name, status, access_token_ttl, refresh_token_ttl, key_rotation_policy, rate_limit_config, created_at, updated_at
		FROM tenants WHERE id = $1
	`
	row := r.db.Pool.QueryRow(ctx, query, id)
	return r.scanTenant(ctx, row)
}

// FindAll retrieves a list of all tenants.
func (r *tenantRepositoryImpl) FindAll(ctx context.Context, limit, offset int) ([]*models.Tenant, *errors.AppError) {
	query := `
		SELECT id, tenant_name, status, access_token_ttl, refresh_token_ttl, key_rotation_policy, rate_limit_config, created_at, updated_at
		FROM tenants ORDER BY created_at DESC LIMIT $1 OFFSET $2
	`
	rows, err := r.db.Pool.Query(ctx, query, limit, offset)
	if err != nil {
		r.log.Error(ctx, "Failed to query all tenants", err)
		return nil, errors.ErrDatabase.WithError(err)
	}
	defer rows.Close()

	tenants := make([]*models.Tenant, 0)
	for rows.Next() {
		tenant, appErr := r.scanTenant(ctx, rows)
		if appErr != nil {
			return nil, appErr
		}
		tenants = append(tenants, tenant)
	}
	return tenants, nil
}

// UpdateConfig updates a tenant's configuration.
func (r *tenantRepositoryImpl) UpdateConfig(ctx context.Context, tenant *models.Tenant) *errors.AppError {
	query := `
		UPDATE tenants SET
			tenant_name = $2,
			status = $3,
			access_token_ttl = $4,
			refresh_token_ttl = $5,
			key_rotation_policy = $6,
			rate_limit_config = $7,
			updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.Pool.Exec(ctx, query,
		tenant.ID, tenant.TenantName, tenant.Status, tenant.AccessTokenTTL,
		tenant.RefreshTokenTTL, tenant.KeyRotationPolicy, tenant.RateLimitConfig,
	)
	if err != nil {
		r.log.Error(ctx, "Failed to update tenant config", err)
		return errors.ErrDatabase.WithError(err)
	}
	return nil
}

func (r *tenantRepositoryImpl) scanTenant(ctx context.Context, row pgx.Row) (*models.Tenant, *errors.AppError) {
	var tenant models.Tenant
	err := row.Scan(
		&tenant.ID, &tenant.TenantName, &tenant.Status, &tenant.AccessTokenTTL, &tenant.RefreshTokenTTL,
		&tenant.KeyRotationPolicy, &tenant.RateLimitConfig, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		r.log.Error(ctx, "Failed to scan tenant row", err)
		return nil, errors.ErrDatabase.WithError(err)
	}
	return &tenant, nil
}

//Personal.AI order the ending
