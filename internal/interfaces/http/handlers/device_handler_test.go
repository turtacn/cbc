package handlers_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
)

func TestNewDeviceHandler(t *testing.T) {
	handler := handlers.NewDeviceHandler()
	assert.NotNil(t, handler)
}
