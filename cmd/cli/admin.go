package cli

import (
	"github.com/spf13/cobra"
)

// adminCmd represents the admin command
var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Administer the CBC service",
}

func init() {
	rootCmd.AddCommand(adminCmd)
}
