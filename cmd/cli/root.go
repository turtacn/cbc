package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when the `cbc-admin` binary is called without any subcommands.
// It provides the entry point for the entire CLI application.
// rootCmd 代表在没有任何子命令的情况下调用 `cbc-admin` 二进制文件时的基本命令。
// 它为整个 CLI 应用程序提供入口点。
var rootCmd = &cobra.Command{
	Use:   "cbc-admin",
	Short: "A CLI tool for administering the Core Banking Component (CBC) service.",
	Long: `cbc-admin is a command-line interface for performing administrative tasks
on the CBC service, such as managing keys, tenants, and compliance settings.`,
}

// Execute is the main entry point for the CLI application.
// It adds all child commands to the root command, parses the command-line arguments,
// and executes the appropriate command. If an error occurs, it prints the error and exits.
// Execute 是 CLI 应用程序的主入口点。
// 它将所有子命令添加到根命令中，解析命令行参数，并执行相应的命令。
// 如果发生错误，它会打印错误并退出。
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
