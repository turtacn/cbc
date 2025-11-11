package main

import (
	"github.com/turtacn/cbc/cmd/cli"
)

// main is the entry point for the cbc-admin command-line tool.
// It delegates all execution to the Execute function provided by the cli package.
// main 是 cbc-admin 命令行工具的入口点。
// 它将所有执行委托给 cli 包提供的 Execute 函数。
func main() {
	cli.Execute()
}
