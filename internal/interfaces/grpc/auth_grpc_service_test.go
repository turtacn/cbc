package grpc_test

import (
	"context"
	"log"
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	pb "github.com/turtacn/cbc/api/proto"
	"github.com/turtacn/cbc/internal/application/dto"
	app_svc "github.com/turtacn/cbc/internal/application/service"
	grpchandlers "github.com/turtacn/cbc/internal/interfaces/grpc"
	"github.com/turtacn/cbc/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

// MockAuthAppService for gRPC test
type MockAuthAppService struct {
	mock.Mock
}

func (m *MockAuthAppService) IssueToken(ctx context.Context, req *dto.TokenIssueRequest) (*dto.TokenPairResponse, *errors.AppError) {
	args := m.Called(ctx, req)
	if args.Get(1) == nil {
		return args.Get(0).(*dto.TokenPairResponse), nil
	}
	return args.Get(0).(*dto.TokenPairResponse), args.Get(1).(*errors.AppError)
}

func (m *MockAuthAppService) RevokeToken(ctx context.Context, req *dto.TokenRevokeRequest) *errors.AppError {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*errors.AppError)
}

func (m *MockAuthAppService) RefreshToken(ctx context.Context, req *dto.TokenRefreshRequest) (*dto.TokenPairResponse, *errors.AppError) {
	args := m.Called(ctx, req)
	if args.Get(1) == nil {
		return args.Get(0).(*dto.TokenPairResponse), nil
	}
	return args.Get(0).(*dto.TokenPairResponse), args.Get(1).(*errors.AppError)
}

func initGRPCServer(authSvc app_svc.AuthAppService) {
	lis = bufconn.Listen(bufSize)
	s := grpchandlers.NewAuthGRPCServer(authSvc, nil, nil, nil) // Real implementation needs more dependencies
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func TestAuthGRPCService_IssueToken(t *testing.T) {
	mockAppSvc := new(MockAuthAppService)
	initGRPCServer(mockAppSvc)

	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	assert.NoError(t, err)
	defer conn.Close()

	client := pb.NewAuthServiceClient(conn)

	// Setup mock
	req := &pb.IssueTokenRequest{TenantId: uuid.New().String()}
	mockResp := &dto.TokenPairResponse{AccessToken: "abc"}
	mockAppSvc.On("IssueToken", mock.Anything, mock.Anything).Return(mockResp, nil)

	resp, err := client.IssueToken(ctx, req)

	assert.NoError(t, err)
	assert.Equal(t, "abc", resp.AccessToken)

	mockAppSvc.AssertExpectations(t)
}

//Personal.AI order the ending
