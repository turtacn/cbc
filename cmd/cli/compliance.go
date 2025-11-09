package cli

import (
	"github.com/spf13/cobra"
)

// complianceCmd represents the compliance command
var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Compliance-related commands",
}

func init() {
	adminCmd.AddCommand(complianceCmd)
}
