//go:build test
package fakes

import (
	"context"
	"time"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
)

// FakeAuditProducer is a mock implementation of domain.AuditService for testing purposes.
type FakeAuditProducer struct {
	ch chan models.AuditEvent
}

// NewFakeAuditProducer creates a new FakeAuditProducer.
func NewFakeAuditProducer(buf int) *FakeAuditProducer {
	return &FakeAuditProducer{ch: make(chan models.AuditEvent, buf)}
}

// LogEvent logs an audit event to the channel.
func (p *FakeAuditProducer) LogEvent(ctx context.Context, event models.AuditEvent) error {
	p.ch <- event
	return nil
}

// DrainOne retrieves one audit event from the channel.
func (p *FakeAuditProducer) DrainOne(ctx context.Context, timeout time.Duration) (*models.AuditEvent, error) {
	select {
	case m := <-p.ch:
		return &m, nil
	case <-time.After(timeout):
		return nil, context.DeadlineExceeded
	}
}

var _ service.AuditService = (*FakeAuditProducer)(nil)
