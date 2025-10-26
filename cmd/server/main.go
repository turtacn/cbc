package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/turtacn/cbc/internal/serverlite"
)

func main() {
	// For simplicity, we'll use a hardcoded signing key for the E2E server.
	// In a real application, this would come from a secure configuration source.
	signingKey := []byte("your-super-secret-hmac-key-for-e2e-testing")

	// Create and start the lightweight server
	server := serverlite.NewServer(":8080", signingKey)
	server.Start()
	log.Println("E2E serverlite started on :8080")

	// Wait for termination signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Gracefully shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Stop(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}
