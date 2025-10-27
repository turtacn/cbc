//go:build !e2e

package main

import "testing"

func TestNoOp(t *testing.T) {
	// This is a no-op test to ensure the `main` package is treated as a test package
	// and is excluded from the normal build.
}
