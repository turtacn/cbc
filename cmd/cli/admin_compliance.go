package cli

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// complianceReportCmd defines the `cbc-admin compliance report` command.
// It connects to the database and generates a simple report of compliance classes for each tenant.
// complianceReportCmd 定义了 `cbc-admin compliance report` 命令。
// 它连接到数据库并为每个租户生成一个简单的合规性类别报告。
var complianceReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a basic compliance report for all tenants",
	Long: `Connects to the database and queries tenant configurations to produce a report
showing the assigned compliance class for each tenant.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dbURL, _ := cmd.Flags().GetString("db-url")
		if dbURL == "" {
			return fmt.Errorf("--db-url flag is required")
		}

		dbpool, err := pgxpool.New(context.Background(), dbURL)
		if err != nil {
			return fmt.Errorf("unable to connect to database: %v", err)
		}
		defer dbpool.Close()

		// This is a simplified example. A real-world report would be more comprehensive,
		// potentially joining with other tables to show key rotation status, etc.
		rows, err := dbpool.Query(context.Background(), "SELECT tenant_id, compliance_class FROM tenant_configs")
		if err != nil {
			return fmt.Errorf("failed to query tenant_configs: %w", err)
		}
		defer rows.Close()

		fmt.Println("--- Tenant Compliance Report ---")
		for rows.Next() {
			var tenantID, complianceClass string
			if err := rows.Scan(&tenantID, &complianceClass); err != nil {
				return fmt.Errorf("failed to scan row: %w", err)
			}
			fmt.Printf("  - Tenant: %s, Compliance Class: %s\n", tenantID, complianceClass)
		}
		fmt.Println("---------------------------------")

		return nil
	},
}

// getRiskCmd defines the `cbc-admin compliance get-risk` command.
// It retrieves and displays the current risk profile for a specified tenant.
// getRiskCmd 定义了 `cbc-admin compliance get-risk` 命令。
// 它检索并显示指定租户的当前风险配置文件。
var getRiskCmd = &cobra.Command{
	Use:   "get-risk",
	Short: "Get the dynamic risk profile for a specific tenant",
	Long:  `Queries the database for a tenant's latest anomaly score and predicted threat level.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dbURL, _ := cmd.Flags().GetString("db-url")
		tenantID, _ := cmd.Flags().GetString("tenant")
		if dbURL == "" || tenantID == "" {
			return fmt.Errorf("--db-url and --tenant flags are required")
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
			return fmt.Errorf("failed to query tenant risk scores: %w", err)
		}

		fmt.Printf("Dynamic Risk Profile for Tenant '%s':\n", tenantID)
		fmt.Printf("  - Anomaly Score:    %.4f\n", anomalyScore)
		fmt.Printf("  - Predicted Threat: %s\n", predictedThreat)

		return nil
	},
}

// setRiskCmd defines the `cbc-admin compliance set-risk` command.
// It allows manually setting or updating the risk profile for a tenant, simulating an update from an ML system.
// setRiskCmd 定义了 `cbc-admin compliance set-risk` 命令。
// 它允许手动设置或更新租户的风险配置文件，模拟来自 ML 系统的更新。
var setRiskCmd = &cobra.Command{
	Use:   "set-risk",
	Short: "Manually set the dynamic risk profile for a tenant",
	Long: `Inserts or updates a tenant's risk profile in the database.
This is useful for testing risk-based policies or for manual intervention.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dbURL, _ := cmd.Flags().GetString("db-url")
		tenantID, _ := cmd.Flags().GetString("tenant")
		score, _ := cmd.Flags().GetFloat64("score")
		threat, _ := cmd.Flags().GetString("threat")
		if dbURL == "" || tenantID == "" || threat == "" {
			return fmt.Errorf("--db-url, --tenant, and --threat flags are required")
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
			return fmt.Errorf("failed to upsert tenant risk scores: %w", err)
		}

		fmt.Printf("Successfully set risk profile for tenant '%s'\n", tenantID)
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
