package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/infrastructure/audit"
)

// auditRepository implements the AuditService interface.
type auditRepository struct {
	db        *pgxpool.Pool
	auditCfg  config.AuditConfig
}

// NewAuditRepository creates a new Audit repository.
func NewAuditRepository(db *pgxpool.Pool, auditCfg config.AuditConfig) *auditRepository {
	return &auditRepository{db: db, auditCfg: auditCfg}
}

// LogEvent logs an audit event to the database.
func (r *auditRepository) LogEvent(ctx context.Context, event models.AuditEvent) error {
	sig, err := audit.SignAuditEvent(event, r.auditCfg.SecretKey)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO audit_logs (id, tenant_id, actor, action, target, timestamp, ip_address, details, status_code, event_type, sig)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err = r.db.Exec(ctx, query, event.ID, event.TenantID, event.Actor, event.Action, event.Target, event.Timestamp, event.IPAddress, event.Details, event.StatusCode, event.EventType, sig)
	return err
}
