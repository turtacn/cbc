package cli

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// complianceReportCmd represents the compliance report command
var complianceReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a compliance report",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Database connection string should be passed in via a flag or config file
		dbURL, _ := cmd.Flags().GetString("db-url")
		if dbURL == "" {
			return fmt.Errorf("db-url flag is required")
		}

		dbpool, err := pgxpool.New(context.Background(), dbURL)
		if err != nil {
			return fmt.Errorf("unable to connect to database: %v", err)
		}
		defer dbpool.Close()

		// Query the database and generate the report
		// This is a simplified example. A real report would be more comprehensive.
		rows, err := dbpool.Query(context.Background(), "SELECT tenant_id, compliance_class FROM tenant_configs")
		if err != nil {
			return fmt.Errorf("failed to query tenant_configs: %w", err)
		}
		defer rows.Close()

		fmt.Println("Compliance Report:")
		for rows.Next() {
			var tenantID, complianceClass string
			if err := rows.Scan(&tenantID, &complianceClass); err != nil {
				return fmt.Errorf("failed to scan row: %w", err)
			}
			fmt.Printf("- Tenant: %s, Compliance Class: %s\n", tenantID, complianceClass)
		}

		return nil
	},
}

var getRiskCmd = &cobra.Command{
	Use:   "get-risk",
	Short: "Get the risk profile for a tenant",
	RunE: func(cmd *cobra.Command, args []string) error {
		dbURL, _ := cmd.Flags().GetString("db-url")
		tenantID, _ := cmd.Flags().GetString("tenant")
		if dbURL == "" || tenantID == "" {
			return fmt.Errorf("db-url and tenant flags are required")
		}

		dbpool, err := pgxpool.New(context.Background(), dbURL)
		if err != nil {
			return fmt.Errorf("unable to connect to database: %v", err)
		}
		defer dbpool.Close()

		var anomalyScore float64
		var predictedThreat string
		err = dbpool.QueryRow(context.Background(),
			"SELECT anomaly_score, predicted_threat FROM tenant_risk_scores WHERE tenant_id = $1",
			tenantID).Scan(&anomalyScore, &predictedThreat)
		if err != nil {
			return fmt.Errorf("failed to query tenant_risk_scores: %w", err)
		}

		fmt.Printf("Risk profile for tenant %s:\n", tenantID)
		fmt.Printf("- Anomaly Score: %.4f\n", anomalyScore)
		fmt.Printf("- Predicted Threat: %s\n", predictedThreat)

		return nil
	},
}

var setRiskCmd = &cobra.Command{
	Use:   "set-risk",
	Short: "Set the risk profile for a tenant",
	RunE: func(cmd *cobra.Command, args []string) error {
		dbURL, _ := cmd.Flags().GetString("db-url")
		tenantID, _ := cmd.Flags().GetString("tenant")
		score, _ := cmd.Flags().GetFloat64("score")
		threat, _ := cmd.Flags().GetString("threat")
		if dbURL == "" || tenantID == "" || threat == "" {
			return fmt.Errorf("db-url, tenant, and threat flags are required")
		}

		dbpool, err := pgxpool.New(context.Background(), dbURL)
		if err != nil {
			return fmt.Errorf("unable to connect to database: %v", err)
		}
		defer dbpool.Close()

		_, err = dbpool.Exec(context.Background(),
			`INSERT INTO tenant_risk_scores (tenant_id, anomaly_score, predicted_threat, last_updated)
			 VALUES ($1, $2, $3, NOW())
			 ON CONFLICT (tenant_id) DO UPDATE SET
			 anomaly_score = EXCLUDED.anomaly_score,
			 predicted_threat = EXCLUDED.predicted_threat,
			 last_updated = NOW()`,
			tenantID, score, threat)
		if err != nil {
			return fmt.Errorf("failed to upsert tenant_risk_scores: %w", err)
		}

		fmt.Printf("Successfully set risk profile for tenant %s\n", tenantID)
		return nil
	},
}

func init() {
	complianceCmd.AddCommand(complianceReportCmd)
	complianceReportCmd.Flags().String("db-url", "", "Database connection URL")

	complianceCmd.AddCommand(getRiskCmd)
	getRiskCmd.Flags().String("db-url", "", "Database connection URL")
	getRiskCmd.Flags().String("tenant", "", "Tenant ID")
	getRiskCmd.MarkFlagRequired("tenant")

	complianceCmd.AddCommand(setRiskCmd)
	setRiskCmd.Flags().String("db-url", "", "Database connection URL")
	setRiskCmd.Flags().String("tenant", "", "Tenant ID")
	setRiskCmd.Flags().Float64("score", 0.0, "Anomaly score (0.0 to 1.0)")
	setRiskCmd.Flags().String("threat", "low", "Predicted threat level (low, medium, high)")
	setRiskCmd.MarkFlagRequired("tenant")
}
