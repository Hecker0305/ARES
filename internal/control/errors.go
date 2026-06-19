package control

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// =============================================================================
// ARES ENGINE - CLASSIFIED ERROR SYSTEM
// =============================================================================

// ErrorClass classifies errors for proper handling
type ErrorClass int

const (
	ErrTransient  ErrorClass = iota // Retryable after delay
	ErrPermanent                    // Won't succeed on retry
	ErrConfig                       // Configuration issue
	ErrAuth                         // Authentication/authorization
	ErrLimit                        // Rate/budget/resource limit
	ErrSafety                       // Safety policy blocked
	ErrDependency                   // External dependency failure
	ErrValidation                   // Input validation failure
	ErrInternal                     // Internal bug
	ErrTimeout                      // Operation timed out
)

func (e ErrorClass) String() string {
	switch e {
	case ErrTransient:
		return "transient"
	case ErrPermanent:
		return "permanent"
	case ErrConfig:
		return "configuration"
	case ErrAuth:
		return "authentication"
	case ErrLimit:
		return "limit"
	case ErrSafety:
		return "safety"
	case ErrDependency:
		return "dependency"
	case ErrValidation:
		return "validation"
	case ErrInternal:
		return "internal"
	case ErrTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// ClassifiedError wraps an error with classification metadata
type ClassifiedError struct {
	Err       error
	Class     ErrorClass
	Code      string
	Retryable bool
	Waiver    time.Duration
	Details   string
}

func (e ClassifiedError) Error() string {
	return fmt.Sprintf("[%s] %s: %v", e.Class, e.Code, e.Err)
}

func (e ClassifiedError) Unwrap() error { return e.Err }

// ErrorReporter provides context for error classification
type ErrorReporter struct {
	Component string
	Operation string
	Params    map[string]string
}

// NewClassifiedError creates a classified error
func NewClassifiedError(class ErrorClass, code string, err error) ClassifiedError {
	return ClassifiedError{
		Err:       err,
		Class:     class,
		Code:      code,
		Retryable: class == ErrTransient || class == ErrLimit || class == ErrDependency,
		Waiver:    defaultWaiver(class),
		Details:   "",
	}
}

// WithDetails adds detail context to classified error
func (e ClassifiedError) WithDetails(details string) ClassifiedError {
	e.Details = details
	return e
}

// WithWaiver overrides the default retry waiver
func (e ClassifiedError) WithWaiver(d time.Duration) ClassifiedError {
	e.Waiver = d
	return e
}

func defaultWaiver(class ErrorClass) time.Duration {
	switch class {
	case ErrTransient:
		return 1 * time.Second
	case ErrLimit:
		return 5 * time.Second
	case ErrDependency:
		return 3 * time.Second
	case ErrTimeout:
		return 10 * time.Second
	default:
		return 0
	}
}

// ErrorClassifier classifies raw errors into typed categories
type ErrorClassifier struct{}

// NewErrorClassifier creates a new classifier
func NewErrorClassifier() *ErrorClassifier {
	return &ErrorClassifier{}
}

// Classify determines the error class from an error value
func (c *ErrorClassifier) Classify(err error, reporter ErrorReporter) ClassifiedError {
	if err == nil {
		return ClassifiedError{}
	}

	if ce, ok := err.(ClassifiedError); ok {
		return ce
	}

	errStr := err.Error()
	lower := strings.ToLower(errStr)

	switch {
	case strings.Contains(lower, "timeout"):
		return NewClassifiedError(ErrTimeout, "timeout", err)
	case strings.Contains(lower, "connection refused"):
		return NewClassifiedError(ErrTransient, "conn_refused", err)
	case strings.Contains(lower, "connection reset"):
		return NewClassifiedError(ErrTransient, "conn_reset", err)
	case strings.Contains(lower, "temporary"):
		return NewClassifiedError(ErrTransient, "temporary", err)
	case strings.Contains(lower, "rate limit"):
		return NewClassifiedError(ErrLimit, "rate_limit", err)
	case strings.Contains(lower, "429"):
		return NewClassifiedError(ErrLimit, "http_429", err)
	case strings.Contains(lower, "unauthorized"):
		return NewClassifiedError(ErrAuth, "unauthorized", err)
	case strings.Contains(lower, "forbidden"):
		return NewClassifiedError(ErrAuth, "forbidden", err)
	case strings.Contains(lower, "invalid token"):
		return NewClassifiedError(ErrAuth, "bad_token", err)
	case strings.Contains(lower, "authentication"):
		return NewClassifiedError(ErrAuth, "auth_failure", err)
	case strings.Contains(lower, "validation"):
		return NewClassifiedError(ErrValidation, "validation", err)
	case strings.Contains(lower, "invalid"):
		return NewClassifiedError(ErrValidation, "invalid_input", err)
	case strings.Contains(lower, "malformed"):
		return NewClassifiedError(ErrValidation, "malformed", err)
	case strings.Contains(lower, "blocked"):
		return NewClassifiedError(ErrSafety, "blocked", err)
	case strings.Contains(lower, "denied"):
		return NewClassifiedError(ErrSafety, "denied", err)
	case strings.Contains(lower, "policy"):
		return NewClassifiedError(ErrSafety, "policy", err)
	case strings.Contains(lower, "budget"):
		return NewClassifiedError(ErrLimit, "budget", err)
	case strings.Contains(lower, "404"):
		return NewClassifiedError(ErrPermanent, "not_found", err)
	case strings.Contains(lower, "500"):
		return NewClassifiedError(ErrInternal, "internal_error", err)
	case strings.Contains(lower, "502"):
		return NewClassifiedError(ErrTransient, "bad_gateway", err)
	case strings.Contains(lower, "503"):
		return NewClassifiedError(ErrTransient, "service_unavailable", err)
	case strings.Contains(lower, "dial tcp"):
		return NewClassifiedError(ErrDependency, "tcp_error", err)
	case strings.Contains(lower, "dns"):
		return NewClassifiedError(ErrDependency, "dns_error", err)
	case strings.Contains(lower, "tls"):
		return NewClassifiedError(ErrDependency, "tls_error", err)
	default:
		return NewClassifiedError(ErrInternal, "unknown", err)
	}
}

// HTTPStatusCode maps error class to HTTP status code
func HTTPStatusCode(class ErrorClass) int {
	switch class {
	case ErrTransient:
		return http.StatusServiceUnavailable
	case ErrPermanent:
		return http.StatusBadRequest
	case ErrConfig:
		return 421
	case ErrAuth:
		return http.StatusUnauthorized
	case ErrLimit:
		return http.StatusTooManyRequests
	case ErrSafety:
		return http.StatusForbidden
	case ErrDependency:
		return http.StatusBadGateway
	case ErrValidation:
		return http.StatusBadRequest
	case ErrInternal:
		return http.StatusInternalServerError
	case ErrTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}

// RetryDecision provides retry guidance
type RetryDecision struct {
	Retryable  bool
	MaxRetries int
	NextDelay  time.Duration
}

// GetRetryDecision provides retry guidance for a classified error
func GetRetryDecision(err ClassifiedError, attempt int) RetryDecision {
	if !err.Retryable {
		return RetryDecision{Retryable: false}
	}

	maxRetries := 3
	switch err.Class {
	case ErrLimit:
		maxRetries = 5
	case ErrTransient:
		maxRetries = 3
	case ErrDependency:
		maxRetries = 2
	case ErrTimeout:
		maxRetries = 2
	}

	if attempt >= maxRetries {
		return RetryDecision{Retryable: false}
	}

	delay := err.Waiver * time.Duration(1<<uint(attempt))
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}

	return RetryDecision{
		Retryable:  true,
		MaxRetries: maxRetries,
		NextDelay:  delay,
	}
}

// ResponseError formats a classified error for API responses
type ResponseError struct {
	Error     string        `json:"error"`
	Code      string        `json:"code"`
	Class     string        `json:"class"`
	Retryable bool          `json:"retryable,omitempty"`
	NextRetry time.Duration `json:"next_retry,omitempty"`
}

// ToResponse converts a classified error to an API response
func (e ClassifiedError) ToResponse() ResponseError {
	resp := ResponseError{
		Error: e.Error(),
		Code:  e.Code,
		Class: e.Class.String(),
	}
	if e.Retryable {
		resp.Retryable = true
		resp.NextRetry = e.Waiver
	}
	return resp
}
