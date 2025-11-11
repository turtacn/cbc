package cli

import (
	"github.com/spf13/cobra"
)

// adminCmd represents the root command for all administrative operations.
// It serves as a parent command for subcommands related to service administration.
// adminCmd 代表所有管理操作的根命令。
// 它充当与服务管理相关的子命令的父命令。
var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "A root command for administering the CBC service",
	Long: `The admin command provides a namespace for all administrative tasks,
such as managing tenants, keys, and compliance policies.`,
}

func init() {
	rootCmd.AddCommand(adminCmd)
}
