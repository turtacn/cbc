// Package audit implements the AuditService interface using GORM.
package audit

import (
	"context"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"gorm.io/gorm"
)

// GormAuditService provides a GORM-backed implementation of the AuditService.
// It stores audit events in a relational database.
type GormAuditService struct {
	db *gorm.DB
}

// NewGormAuditService creates and configures a new GormAuditService.
func NewGormAuditService(db *gorm.DB) service.AuditService {
	return &GormAuditService{
		db: db,
	}
}

// LogEvent saves an AuditEvent to the database.
func (s *GormAuditService) LogEvent(ctx context.Context, event models.AuditEvent) error {
	return s.db.WithContext(ctx).Create(&event).Error
}
