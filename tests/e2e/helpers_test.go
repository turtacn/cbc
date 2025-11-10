//go:build integration

package e2e

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
)

var serverCmd *exec.Cmd

func buildCLI(t *testing.T) string {
	t.Helper()
	cliPath := filepath.Join(t.TempDir(), "cbc-admin")
	cmd := exec.Command("go", "build", "-o", cliPath, "../../cmd/cbc-admin")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build CLI: %s", string(output))
	return cliPath
}

func setupTestDB(t *testing.T) string {
	t.Helper()
	dbName := "testdb_" + strings.ReplaceAll(time.Now().Format("20060102150405.000000"), ".", "")
	connStr := "postgres://postgres:password@localhost:5432/postgres?sslmode=disable"
	db, err := sql.Open("pgx", connStr)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec("CREATE DATABASE " + dbName)
	require.NoError(t, err)
	return dbName
}

func runMigrations(t *testing.T, dbName string) {
	t.Helper()
	connStr := fmt.Sprintf("postgres://postgres:password@localhost:5432/%s?sslmode=disable", dbName)
	db, err := sql.Open("pgx", connStr)
	require.NoError(t, err)
	defer db.Close()

	migrationsDir := "../../migrations"
	files, err := ioutil.ReadDir(migrationsDir)
	require.NoError(t, err)

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}
		filePath := filepath.Join(migrationsDir, file.Name())
		content, err := ioutil.ReadFile(filePath)
		require.NoError(t, err)
		_, err = db.Exec(string(content))
		require.NoError(t, err, "failed to apply migration: %s", file.Name())
	}
}

func startServer(t *testing.T, dbName string) {
	t.Helper()
	configContent := fmt.Sprintf(`
database:
  dsn: "postgres://postgres:password@localhost:5432/%s?sslmode=disable"
server:
  port: 8080
internal_server:
  port: 9091
`, dbName)
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	err := ioutil.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	serverCmd = exec.Command("go", "run", "../../cmd/server", "--config", configFile)
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	err = serverCmd.Start()
	require.NoError(t, err)
}

func stopServer(t *testing.T) {
	t.Helper()
	if serverCmd != nil && serverCmd.Process != nil {
		err := serverCmd.Process.Kill()
		if err != nil {
			log.Printf("failed to kill server process: %v", err)
		}
	}
}

func cleanupTestDB(t *testing.T, dbName string) {
	t.Helper()
	connStr := "postgres://postgres:password@localhost:5432/postgres?sslmode=disable"
	db, err := sql.Open("pgx", connStr)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec("DROP DATABASE " + dbName)
	require.NoError(t, err)
}
