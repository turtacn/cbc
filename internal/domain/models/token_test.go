package models

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

// internal/domain/models/token_test.go
package models

import (
"testing"
"time"

"github.com/google/uuid"
"github.com/stretchr/testify/assert"
"github.com/turtacn/cbc/pkg/errors"
)

func TestToken_Validate(t *testing.T) {
	tests := []struct {
		name    string
		token   *Token
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid access token",
			token: &Token{
				ID:        uuid.New(),
				JTI:       uuid.New().String(),
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: TokenTypeAccess,
				Scope:     "agent:read agent:write",
				IssuedAt:  time.Now().Add(-1 * time.Minute),
				ExpiresAt: time.Now().Add(15 * time.Minute),
				CreatedAt: time.Now(),
			},
			wantErr: false,
		},
		{
			name: "Valid refresh token",
			token: &Token{
				ID:        uuid.New(),
				JTI:       uuid.New().String(),
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: TokenTypeRefresh,
				Scope:     "agent:read",
				IssuedAt:  time.Now().Add(-1 * time.Hour),
				ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
				CreatedAt: time.Now(),
			},
			wantErr: false,
		},
		{
			name: "Empty JTI",
			token: &Token{
				JTI:       "",
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: TokenTypeAccess,
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
			wantErr: true,
			errMsg:  "JTI is required",
		},
		{
			name: "Zero TenantID",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.Nil,
				DeviceID:  uuid.New(),
				TokenType: TokenTypeAccess,
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
			wantErr: true,
			errMsg:  "TenantID is required",
		},
		{
			name: "Zero DeviceID",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New(),
				DeviceID:  uuid.Nil,
				TokenType: TokenTypeAccess,
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
			wantErr: true,
			errMsg:  "DeviceID is required",
		},
		{
			name: "Invalid token type",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: "invalid_type",
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
			wantErr: true,
			errMsg:  "invalid TokenType",
		},
		{
			name: "ExpiresAt before IssuedAt",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: TokenTypeAccess,
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			wantErr: true,
			errMsg:  "ExpiresAt must be after IssuedAt",
		},
		{
			name: "Zero IssuedAt",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: TokenTypeAccess,
				IssuedAt:  time.Time{},
				ExpiresAt: time.Now().Add(15 * time.Minute),
			},
			wantErr: true,
			errMsg:  "IssuedAt is required",
		},
		{
			name: "Zero ExpiresAt",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: TokenTypeAccess,
				IssuedAt:  time.Now(),
				ExpiresAt: time.Time{},
			},
			wantErr: true,
			errMsg:  "ExpiresAt is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.token.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

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

func TestToken_IsActive(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		token     *Token
		want      bool
		wantErr   bool
		errType   error
	}{
		{
			name: "Active token",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: TokenTypeAccess,
				IssuedAt:  now.Add(-1 * time.Minute),
				ExpiresAt: now.Add(15 * time.Minute),
				RevokedAt: nil,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Expired token",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: TokenTypeAccess,
				IssuedAt:  now.Add(-2 * time.Hour),
				ExpiresAt: now.Add(-1 * time.Hour),
				RevokedAt: nil,
			},
			want:    false,
			wantErr: true,
			errType: errors.ErrTokenExpired,
		},
		{
			name: "Revoked token",
			token: &Token{
				JTI:       uuid.New().String(),
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: TokenTypeAccess,
				IssuedAt:  now.Add(-1 * time.Minute),
				ExpiresAt: now.Add(15 * time.Minute),
				RevokedAt: &now,
			},
			want:    false,
			wantErr: true,
			errType: errors.ErrTokenRevoked,
		},
		{
			name: "Invalid token - validation fails",
			token: &Token{
				JTI:       "",
				TenantID:  uuid.New(),
				DeviceID:  uuid.New(),
				TokenType: TokenTypeAccess,
				IssuedAt:  now,
				ExpiresAt: now.Add(15 * time.Minute),
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.token.IsActive()
			assert.Equal(t, tt.want, got)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestToken_GetRemainingLifetime(t *testing.T) {
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
			got := token.GetRemainingLifetime()
			// 允许 1 秒误差（测试执行时间）
			assert.InDelta(t, tt.want.Seconds(), got.Seconds(), 1.0)
		})
	}
}

//Personal.AI order the ending
