package dto

import (
	"time"

	"github.com/turtacn/cbc/pkg/errors"
)

// APIResponse 通用 API 响应结构
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *ErrorDTO   `json:"error,omitempty"`
	TraceID   string      `json:"trace_id,omitempty"`
	Timestamp int64       `json:"timestamp"`
}

// ErrorDTO 错误信息 DTO
type ErrorDTO struct {
	Code        string            `json:"code"`
	Message     string            `json:"message"`
	Description string            `json:"description,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	ErrorURI    string            `json:"error_uri,omitempty"`
}

// ValidationErrorDTO 验证错误 DTO
type ValidationErrorDTO struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value,omitempty"`
	Message string `json:"message"`
}

// PaginationResponse 分页响应元数据
type PaginationResponse struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// SuccessResponse 创建成功响应
func SuccessResponse(data interface{}, traceID string) *APIResponse {
	return &APIResponse{
		Success:   true,
		Data:      data,
		TraceID:   traceID,
		Timestamp: time.Now().Unix(),
	}
}

// ErrorResponse 创建错误响应
func ErrorResponse(err error, traceID string) *APIResponse {
	var errorDTO *ErrorDTO

	switch e := err.(type) {
	case *errors.AppError:
		errorDTO = &ErrorDTO{
			Code:        e.Code,
			Message:     e.Message,
			Description: e.Description,
			Details:     e.Details,
			ErrorURI:    generateErrorURI(e.Code),
		}
	default:
		errorDTO = &ErrorDTO{
			Code:        errors.ErrCodeInternal,
			Message:     "Internal server error",
			Description: err.Error(),
			ErrorURI:    generateErrorURI(errors.ErrCodeInternal),
		}
	}

	return &APIResponse{
		Success:   false,
		Error:     errorDTO,
		TraceID:   traceID,
		Timestamp: time.Now().Unix(),
	}
}

// ValidationErrorResponse 创建验证错误响应
func ValidationErrorResponse(validationErrors []ValidationErrorDTO, traceID string) *APIResponse {
	details := make(map[string]string)
	for _, ve := range validationErrors {
		details[ve.Field] = ve.Message
	}

	return &APIResponse{
		Success: false,
		Error: &ErrorDTO{
			Code:        errors.ErrCodeInvalidRequest,
			Message:     "Validation failed",
			Description: "One or more fields failed validation",
			Details:     details,
			ErrorURI:    generateErrorURI(errors.ErrCodeInvalidRequest),
		},
		TraceID:   traceID,
		Timestamp: time.Now().Unix(),
	}
}

// UnauthorizedResponse 创建未授权响应
func UnauthorizedResponse(message string, traceID string) *APIResponse {
	return &APIResponse{
		Success: false,
		Error: &ErrorDTO{
			Code:        errors.ErrCodeUnauthorized,
			Message:     "Unauthorized",
			Description: message,
			ErrorURI:    generateErrorURI(errors.ErrCodeUnauthorized),
		},
		TraceID:   traceID,
		Timestamp: time.Now().Unix(),
	}
}

// ForbiddenResponse 创建禁止访问响应
func ForbiddenResponse(message string, traceID string) *APIResponse {
	return &APIResponse{
		Success: false,
		Error: &ErrorDTO{
			Code:        errors.ErrCodeForbidden,
			Message:     "Forbidden",
			Description: message,
			ErrorURI:    generateErrorURI(errors.ErrCodeForbidden),
		},
		TraceID:   traceID,
		Timestamp: time.Now().Unix(),
	}
}

// NotFoundResponse 创建资源未找到响应
func NotFoundResponse(resource string, traceID string) *APIResponse {
	return &APIResponse{
		Success: false,
		Error: &ErrorDTO{
			Code:        errors.ErrCodeNotFound,
			Message:     "Resource not found",
			Description: resource + " not found",
			ErrorURI:    generateErrorURI(errors.ErrCodeNotFound),
		},
		TraceID:   traceID,
		Timestamp: time.Now().Unix(),
	}
}

// RateLimitExceededResponse 创建速率限制响应
func RateLimitExceededResponse(retryAfter int, traceID string) *APIResponse {
	return &APIResponse{
		Success: false,
		Error: &ErrorDTO{
			Code:        errors.ErrCodeRateLimitExceeded,
			Message:     "Rate limit exceeded",
			Description: "Too many requests, please try again later",
			Details: map[string]string{
				"retry_after": string(rune(retryAfter)),
			},
			ErrorURI: generateErrorURI(errors.ErrCodeRateLimitExceeded),
		},
		TraceID:   traceID,
		Timestamp: time.Now().Unix(),
	}
}

// ServiceUnavailableResponse 创建服务不可用响应
func ServiceUnavailableResponse(message string, traceID string) *APIResponse {
	return &APIResponse{
		Success: false,
		Error: &ErrorDTO{
			Code:        errors.ErrCodeServiceUnavailable,
			Message:     "Service temporarily unavailable",
			Description: message,
			ErrorURI:    generateErrorURI(errors.ErrCodeServiceUnavailable),
		},
		TraceID:   traceID,
		Timestamp: time.Now().Unix(),
	}
}

// ConflictResponse 创建冲突响应
func ConflictResponse(message string, traceID string) *APIResponse {
	return &APIResponse{
		Success: false,
		Error: &ErrorDTO{
			Code:        errors.ErrCodeConflict,
			Message:     "Resource conflict",
			Description: message,
			ErrorURI:    generateErrorURI(errors.ErrCodeConflict),
		},
		TraceID:   traceID,
		Timestamp: time.Now().Unix(),
	}
}

// generateErrorURI 生成错误文档 URI
func generateErrorURI(code string) string {
	baseURL := "https://docs.cloudbrain.cert/errors"
	return baseURL + "#" + code
}

// NewValidationError 创建验证错误 DTO
func NewValidationError(field, tag, value, message string) ValidationErrorDTO {
	return ValidationErrorDTO{
		Field:   field,
		Tag:     tag,
		Value:   value,
		Message: message,
	}
}

// WithPagination 添加分页信息到响应
func (r *APIResponse) WithPagination(page, pageSize int, total int64) *APIResponse {
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	if dataMap, ok := r.Data.(map[string]interface{}); ok {
		dataMap["pagination"] = PaginationResponse{
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		}
	}

	return r
}

// WithMetadata 添加元数据到响应
func (r *APIResponse) WithMetadata(key string, value interface{}) *APIResponse {
	if dataMap, ok := r.Data.(map[string]interface{}); ok {
		dataMap[key] = value
	} else {
		r.Data = map[string]interface{}{
			"result":  r.Data,
			key:       value,
		}
	}
	return r
}

//Personal.AI order the ending
