//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type AIDrivenSecurityE2ESuite struct {
	suite.Suite
	cliPath string
	dbName  string
}

func (s *AIDrivenSecurityE2ESuite) SetupSuite() {
	if os.Getenv("SKIP_DOCKER_TESTS") != "" {
		s.T().Skip("Skipping e2e tests in CI")
	}
	s.cliPath = buildCLI(s.T())
	s.dbName = setupTestDB(s.T())
	runMigrations(s.T(), s.dbName)

	// Start the server in the background
	startServer(s.T(), s.dbName)
	time.Sleep(2 * time.Second) // Wait for server to start
}

func (s *AIDrivenSecurityE2ESuite) TearDownSuite() {
	stopServer(s.T())
	cleanupTestDB(s.T(), s.dbName)
}

func (s *AIDrivenSecurityE2ESuite) TestPolicyTuningFlow() {
	tenantID := "tenant-e2e-ai-sec"
	tenantName := "E2E AI Security Tenant"

	// 1. Create Tenant
	cmd := exec.Command(s.cliPath, "tenants", "create", "--id", tenantID, "--name", tenantName, "--class", "L3")
	output, err := cmd.CombinedOutput()
	s.Require().NoError(err, string(output))

	// 2. Low Risk: Rotate key, should succeed
	s.Run("LowRiskRotationSucceeds", func() {
		// Ensure risk is low (default is 0)
		cmd := exec.Command(s.cliPath, "key", "rotate", "--tenant", tenantID)
		output, err := cmd.CombinedOutput()
		s.Require().NoError(err, string(output))
		s.Contains(string(output), "Key rotation successful for tenant")
	})

	// 3. High Risk via CLI: Set risk score high
	s.Run("SetRiskViaCLI", func() {
		cmd := exec.Command(s.cliPath, "compliance", "set-risk", "--tenant", tenantID, "--score", "0.95", "--threat", "high")
		output, err := cmd.CombinedOutput()
		s.Require().NoError(err, string(output))
	})

	// 4. Policy Tuner Blocks: Attempt rotation, should fail
	s.Run("HighRiskRotationFails", func() {
		cmd := exec.Command(s.cliPath, "key", "rotate", "--tenant", tenantID)
		output, err := cmd.CombinedOutput()
		s.Require().Error(err, "Expected command to fail")
		s.Contains(string(output), "policy violation: high anomaly score")
	})

	// 5. Reset via Internal API: Set risk score low
	s.Run("ResetRiskViaAPI", func() {
		payload := struct {
			TenantID     string  `json:"tenant_id"`
			AnomalyScore float64 `json:"anomaly_score"`
		}{
			TenantID:     tenantID,
			AnomalyScore: 0.1,
		}

		body, err := json.Marshal(payload)
		s.Require().NoError(err)

		req, err := http.NewRequestWithContext(context.Background(), "POST", "http://localhost:9091/_internal/ml/risk", bytes.NewBuffer(body))
		s.Require().NoError(err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		s.Require().NoError(err)
		defer resp.Body.Close()
		s.Equal(http.StatusOK, resp.StatusCode)
	})

	// 6. Low Risk Pass Again: Rotate key, should succeed
	s.Run("LowRiskRotationSucceedsAgain", func() {
		cmd := exec.Command(s.cliPath, "key", "rotate", "--tenant", tenantID)
		output, err := cmd.CombinedOutput()
		s.Require().NoError(err, string(output))
		s.Contains(string(output), "Key rotation successful for tenant")
	})
}

func TestAIDrivenSecurityE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	suite.Run(t, new(AIDrivenSecurityE2ESuite))
}
