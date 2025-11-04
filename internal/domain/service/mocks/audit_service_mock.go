package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/domain/models"
)

type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) LogEvent(ctx context.Context, event models.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}
