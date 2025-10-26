// internal/infrastructure/persistence/postgres/audit_repo_impl.go
package postgres

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/turtacn/cbc/internal/domain/repository"
)

type AuditRepo struct{ db *pgxpool.Pool }

func NewAuditRepo(db *pgxpool.Pool) repository.AuditRepo {
	return &AuditRepo{db: db}
}

func (r *AuditRepo) Write(event string, payload map[string]any) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	const q = `insert into audit_logs (event, payload) values ($1, $2)`
	_, err = r.db.Exec(context.Background(), q, event, payloadBytes)
	return err
}
