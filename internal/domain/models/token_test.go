package models_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/constants"
)

func TestToken_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"not expired", time.Now().Add(1 * time.Hour), false},
		{"expired", time.Now().Add(-1 * time.Hour), true},
		{"borderline", time.Now(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &models.Token{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.want, token.IsExpired())
		})
	}
}

func TestToken_IsRevoked(t *testing.T) {
	revokedTime := time.Now()
	tests := []struct {
		name      string
		revokedAt *time.Time
		want      bool
	}{
		{"not revoked", nil, false},
		{"revoked", &revokedTime, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &models.Token{RevokedAt: tt.revokedAt}
			assert.Equal(t, tt.want, token.IsRevoked())
		})
	}
}

func TestToken_CanRefresh(t *testing.T) {
	tests := []struct {
		name      string
		tokenType constants.TokenType
		isValid   bool
		want      bool
	}{
		{"valid refresh token", constants.RefreshToken, true, true},
		{"invalid refresh token", constants.RefreshToken, false, false},
		{"access token", constants.AccessToken, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &models.Token{TokenType: tt.tokenType}
			if !tt.isValid {
				token.ExpiresAt = time.Now().Add(-1 * time.Hour)
			} else {
				token.ExpiresAt = time.Now().Add(1 * time.Hour)
			}
			assert.Equal(t, tt.want, token.CanRefresh())
		})
	}
}

//Personal.AI order the ending
