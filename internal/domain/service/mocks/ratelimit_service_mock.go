package mocks

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/domain/service"
)

// MockRateLimitService is a mock implementation of RateLimitService
type MockRateLimitService struct {
	mock.Mock
}

func (m *MockRateLimitService) Allow(
	ctx context.Context,
	dimension service.RateLimitDimension,
	key string,
	identifier string,
) (bool, int, time.Time, error) {
	args := m.Called(ctx, dimension, key, identifier)
	return args.Bool(0), args.Int(1), args.Get(2).(time.Time), args.Error(3)
}
