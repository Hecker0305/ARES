package engineerrors

import (
	"fmt"
	"net/http"
)

type Code string

const (
	CodeNotFound         Code = "NOT_FOUND"
	CodeInvalidInput     Code = "INVALID_INPUT"
	CodeAlreadyExists    Code = "ALREADY_EXISTS"
	CodeInternal         Code = "INTERNAL_ERROR"
	CodeNotSupported     Code = "NOT_SUPPORTED"
	CodeRateLimited      Code = "RATE_LIMITED"
	CodeUnauthorized     Code = "UNAUTHORIZED"
	CodeResourceExceeded Code = "RESOURCE_EXCEEDED"
	CodeTimeout          Code = "TIMEOUT"
	CodeUnavailable      Code = "UNAVAILABLE"
)

type EngineError struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
	Err     error  `json:"-"`
}

func (e *EngineError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Detail)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *EngineError) Unwrap() error {
	return e.Err
}

func (e *EngineError) HTTPStatus() int {
	switch e.Code {
	case CodeNotFound:
		return http.StatusNotFound
	case CodeInvalidInput:
		return http.StatusBadRequest
	case CodeAlreadyExists:
		return http.StatusConflict
	case CodeNotSupported:
		return http.StatusNotImplemented
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeResourceExceeded:
		return http.StatusTooManyRequests
	case CodeTimeout:
		return http.StatusGatewayTimeout
	case CodeUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func New(code Code, msg string) *EngineError {
	return &EngineError{Code: code, Message: msg}
}

func Newf(code Code, format string, args ...interface{}) *EngineError {
	return &EngineError{Code: code, Message: fmt.Sprintf(format, args...)}
}

func Wrap(code Code, msg string, err error) *EngineError {
	return &EngineError{Code: code, Message: msg, Err: err}
}

func Wrapf(code Code, err error, format string, args ...interface{}) *EngineError {
	return &EngineError{Code: code, Message: fmt.Sprintf(format, args...), Err: err}
}

func NotFound(name string) *EngineError {
	return New(CodeNotFound, fmt.Sprintf("%s not found", name))
}

func InvalidInput(msg string) *EngineError {
	return New(CodeInvalidInput, msg)
}

func Internal(msg string) *EngineError {
	return New(CodeInternal, msg)
}

func RateLimited() *EngineError {
	return New(CodeRateLimited, "rate limit exceeded")
}

func ResourceExceeded(resource string, limit int) *EngineError {
	return Newf(CodeResourceExceeded, "%s exceeds limit of %d", resource, limit)
}

func WriteHTTP(w http.ResponseWriter, err error) {
	ee, ok := err.(*EngineError)
	if !ok {
		ee = &EngineError{Code: CodeInternal, Message: err.Error()}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(ee.HTTPStatus())
	fmt.Fprintf(w, `{"error":{"code":"%s","message":"%s"}}`, ee.Code, ee.Message)
}
