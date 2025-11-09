package postgres

import (
	"context"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"gorm.io/gorm"
)

// klrRepository implements the KeyLifecycleRegistry interface.
type klrRepository struct {
	db *gorm.DB
}

// NewKLRRepository creates a new KLR repository.
func NewKLRRepository(db *gorm.DB) service.KeyLifecycleRegistry {
	return &klrRepository{db: db}
}

// LogEvent logs a key lifecycle event to the database.
func (r *klrRepository) LogEvent(ctx context.Context, event models.KLREvent) error {
	return r.db.WithContext(ctx).Create(&event).Error
}
