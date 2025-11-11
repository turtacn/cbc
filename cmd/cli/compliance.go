package cli

import (
	"github.com/spf13/cobra"
)

// complianceCmd represents the root command for all compliance-related operations.
// It is a subcommand of the `admin` command.
// complianceCmd 代表所有与合规性相关的操作的根命令。
// 它是 `admin` 命令的子命令。
var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Commands for managing compliance and risk profiles",
	Long:  `Provides subcommands for generating compliance reports and managing tenant risk scores.`,
}

func init() {
	adminCmd.AddCommand(complianceCmd)
}
