//go:build unit
// +build unit

package tests

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/suite"
	"github.com/turtacn/cbc/internal/domain/service"
	redisInfra "github.com/turtacn/cbc/internal/infrastructure/redis"
)

type DeviceAuthStoreTestSuite struct {
	suite.Suite
	mr         *miniredis.Miniredis
	client     *redis.Client
	store      service.DeviceAuthStore
	ctx        context.Context
}

func (s *DeviceAuthStoreTestSuite) SetupTest() {
	var err error
	s.mr, err = miniredis.Run()
	s.Require().NoError(err)

	s.client = redis.NewClient(&redis.Options{
		Addr: s.mr.Addr(),
	})
	s.store = redisInfra.NewRedisDeviceAuthStore(s.client)
	s.ctx = context.Background()
}

func (s *DeviceAuthStoreTestSuite) TearDownTest() {
	s.mr.Close()
}

func TestDeviceAuthStoreTestSuite(t *testing.T) {
	suite.Run(t, new(DeviceAuthStoreTestSuite))
}

func (s *DeviceAuthStoreTestSuite) TestCreateAndGetSession() {
	expiresAt := time.Now().Add(10 * time.Minute)
	session := &service.DeviceAuthSession{
		DeviceCode: "test_dc",
		UserCode:   "test_uc",
		ClientID:   "test_client",
		Scope:      "read",
		Status:     "pending",
		ExpiresAt:  expiresAt,
		Interval:   5 * time.Second,
	}

	err := s.store.CreateSession(s.ctx, session)
	s.Require().NoError(err)

	s.mr.FastForward(1 * time.Second)

	// Get by device code
	retrievedByDC, err := s.store.GetSessionByDeviceCode(s.ctx, "test_dc")
	s.Require().NoError(err)
	s.Require().NotNil(retrievedByDC)
	s.Equal(session.UserCode, retrievedByDC.UserCode)
	s.WithinDuration(expiresAt, retrievedByDC.ExpiresAt, time.Second)


	// Get by user code
	retrievedByUC, err := s.store.GetSessionByUserCode(s.ctx, "test_uc")
	s.Require().NoError(err)
	s.Require().NotNil(retrievedByUC)
	s.Equal(session.DeviceCode, retrievedByUC.DeviceCode)

	// Check TTL
	dcKey := "dev_auth:dc:test_dc"
	ucKey := "dev_auth:uc:test_uc"
	s.True(s.mr.Exists(dcKey))
	s.True(s.mr.Exists(ucKey))
	s.InDelta(10*time.Minute, s.mr.TTL(dcKey), float64(1*time.Second))
	s.InDelta(10*time.Minute, s.mr.TTL(ucKey), float64(1*time.Second))


	s.mr.FastForward(11 * time.Minute)
	s.False(s.mr.Exists(dcKey))
	s.False(s.mr.Exists(ucKey))
}


func (s *DeviceAuthStoreTestSuite) TestSessionStateTransitions() {
	session := &service.DeviceAuthSession{
		DeviceCode: "state_dc",
		UserCode:   "state_uc",
		ClientID:   "state_client",
		Status:     "pending",
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}
	err := s.store.CreateSession(s.ctx, session)
	s.Require().NoError(err)

	// Approve
	err = s.store.ApproveSession(s.ctx, "state_uc", "tenant1", "user1")
	s.Require().NoError(err)

	approvedSession, err := s.store.GetSessionByDeviceCode(s.ctx, "state_dc")
	s.Require().NoError(err)
	s.Equal("approved", approvedSession.Status)
	s.Equal("tenant1", approvedSession.TenantID)
	s.Equal("user1", approvedSession.Subject)

	// Deny
	err = s.store.DenySession(s.ctx, "state_uc")
	s.Require().NoError(err)

	deniedSession, err := s.store.GetSessionByDeviceCode(s.ctx, "state_dc")
	s.Require().NoError(err)
	s.Equal("denied", deniedSession.Status)
}

func (s *DeviceAuthStoreTestSuite) TestTouchPoll() {
	session := &service.DeviceAuthSession{
		DeviceCode: "poll_dc",
		UserCode:   "poll_uc",
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}
	err := s.store.CreateSession(s.ctx, session)
	s.Require().NoError(err)

	// last poll time should be zero initially
	retrieved, err := s.store.GetSessionByDeviceCode(s.ctx, "poll_dc")
	s.Require().NoError(err)
	s.True(retrieved.LastPollAt.IsZero())

	// touch poll
	err = s.store.TouchPoll(s.ctx, "poll_dc")
	s.Require().NoError(err)

	s.mr.FastForward(1 * time.Second)

	// last poll time should be updated
	retrieved, err = s.store.GetSessionByDeviceCode(s.ctx, "poll_dc")
	s.Require().NoError(err)
	s.WithinDuration(time.Now(), retrieved.LastPollAt, 2*time.Second)
}

func (s *DeviceAuthStoreTestSuite) TestGetNonExistentSession() {
	retrieved, err := s.store.GetSessionByDeviceCode(s.ctx, "non_existent_dc")
	s.Require().NoError(err)
	s.Nil(retrieved)

	retrieved, err = s.store.GetSessionByUserCode(s.ctx, "non_existent_uc")
	s.Require().NoError(err)
	s.Nil(retrieved)
}

// Helper to get raw session data from miniredis for debugging
func (s *DeviceAuthStoreTestSuite) getRawSession(deviceCode string) (string, error) {
	return s.mr.Get("dev_auth:dc:" + deviceCode)
}
