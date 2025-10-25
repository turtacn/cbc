package dto

import (
	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/pkg/errors"
)

// APIResponse is the standardized JSON response structure.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *ErrorDTO   `json:"error,omitempty"`
	TraceID string      `json:"trace_id,omitempty"`
}

// ErrorDTO represents the error structure in the JSON response.
type ErrorDTO struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// NewSuccessResponse creates a success response with data.
func NewSuccessResponse(data interface{}, traceID string) APIResponse {
	return APIResponse{
		Success: true,
		Data:    data,
		TraceID: traceID,
	}
}

// NewErrorResponse creates a failure response from an AppError.
func NewErrorResponse(err *errors.AppError, traceID string) APIResponse {
	return APIResponse{
		Success: false,
		Error: &ErrorDTO{
			Code:    string(err.Code),
			Message: err.Message,
			Details: err.Details,
		},
		TraceID: traceID,
	}
}

// SendSuccess sends a standardized success response.
func SendSuccess(c *gin.Context, httpStatus int, data interface{}) {
	traceID, _ := c.Get("trace_id")
	c.JSON(httpStatus, NewSuccessResponse(data, traceID.(string)))
}

// SendError sends a standardized error response.
func SendError(c *gin.Context, err *errors.AppError) {
	traceID, _ := c.Get("trace_id")
	c.JSON(err.HTTPStatus, NewErrorResponse(err, traceID.(string)))
}

//Personal.AI order the ending
