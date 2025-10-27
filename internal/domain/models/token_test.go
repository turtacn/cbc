package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/pkg/constants"
)

func TestToken_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "Not expired - future expiration",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "Expired - past expiration",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "Boundary - expires at current time",
			expiresAt: time.Now(),
			want:      true, // 边界情况视为已过期
		},
		{
			name:      "Expires in 1 second",
			expiresAt: time.Now().Add(1 * time.Second),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{
				ExpiresAt: tt.expiresAt,
			}
			got := token.IsExpired()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestToken_IsRevoked(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		revokedAt *time.Time
		want      bool
	}{
		{
			name:      "Not revoked - nil RevokedAt",
			revokedAt: nil,
			want:      false,
		},
		{
			name:      "Revoked - has RevokedAt timestamp",
			revokedAt: &now,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{
				RevokedAt: tt.revokedAt,
			}
			got := token.IsRevoked()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestToken_IsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name  string
		token *Token
		want  bool
	}{
		{
			name: "Active token",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New().String(),
				DeviceID:  uuid.New().String(),
				TokenType: constants.TokenTypeAccess,
				IssuedAt:  now.Add(-1 * time.Minute),
				ExpiresAt: now.Add(15 * time.Minute),
				RevokedAt: nil,
			},
			want: true,
		},
		{
			name: "Expired token",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New().String(),
				DeviceID:  uuid.New().String(),
				TokenType: constants.TokenTypeAccess,
				IssuedAt:  now.Add(-2 * time.Hour),
				ExpiresAt: now.Add(-1 * time.Hour),
				RevokedAt: nil,
			},
			want: false,
		},
		{
			name: "Revoked token",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New().String(),
				DeviceID:  uuid.New().String(),
				TokenType: constants.TokenTypeAccess,
				IssuedAt:  now.Add(-1 * time.Minute),
				ExpiresAt: now.Add(15 * time.Minute),
				RevokedAt: &now,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.token.IsValid()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestToken_TimeUntilExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      time.Duration
	}{
		{
			name:      "1 hour remaining",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      1 * time.Hour,
		},
		{
			name:      "Already expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      0,
		},
		{
			name:      "5 minutes remaining",
			expiresAt: time.Now().Add(5 * time.Minute),
			want:      5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{
				ExpiresAt: tt.expiresAt,
			}
			got := token.TimeUntilExpiry()
			// 允许 1 秒误差（测试执行时间）
			assert.InDelta(t, tt.want.Seconds(), got.Seconds(), 1.0)
		})
	}
}
