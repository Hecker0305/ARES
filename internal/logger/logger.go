package logger

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

func (l Level) String() string {
	switch l {
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warn"
	case ErrorLevel:
		return "error"
	case FatalLevel:
		return "fatal"
	default:
		return "unknown"
	}
}

type Fields map[string]interface{}

type Logger struct {
	mu      sync.RWMutex
	level   Level
	output  io.Writer
	service string
	version string
	env     string
}

var defaultLogger *Logger
var defaultOnce sync.Once

func Init(service, version, env string, level Level) *Logger {
	defaultOnce.Do(func() {
		defaultLogger = &Logger{
			level:   level,
			output:  os.Stderr,
			service: service,
			version: version,
			env:     env,
		}
	})
	return defaultLogger
}

func Get() *Logger {
	if defaultLogger == nil {
		return Init("ares", "dev", "development", InfoLevel)
	}
	return defaultLogger
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Service   string `json:"service"`
	Version   string `json:"version,omitempty"`
	Env       string `json:"env,omitempty"`
	Message   string `json:"message"`
	Caller    string `json:"caller,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
	SpanID    string `json:"span_id,omitempty"`
	Fields    Fields `json:"fields,omitempty"`
	Error     string `json:"error,omitempty"`
	Stack     string `json:"stack,omitempty"`
}

func (l *Logger) log(level Level, msg string, fields Fields) {
	if level < l.level {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level.String(),
		Service:   l.service,
		Version:   l.version,
		Env:       l.env,
		Message:   msg,
		Fields:    RedactFields(fields),
	}

	if _, file, line, ok := runtime.Caller(2); ok {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		entry.Caller = fmt.Sprintf("%s:%d", short, line)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("ERROR: failed to marshal log entry: %v", err)
		return
	}
	fmt.Fprintln(l.output, string(data))
}

func (l *Logger) Debug(msg string, fields Fields) { l.log(DebugLevel, msg, fields) }
func (l *Logger) Info(msg string, fields Fields)  { l.log(InfoLevel, msg, fields) }
func (l *Logger) Warn(msg string, fields Fields)  { l.log(WarnLevel, msg, fields) }
func (l *Logger) Error(msg string, fields Fields) { l.log(ErrorLevel, msg, fields) }

func (l *Logger) Fatal(msg string, fields Fields) {
	l.log(FatalLevel, msg, fields)
	os.Exit(1)
}

func (l *Logger) WithFields(fields Fields) Fields {
	return fields
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

var sensitiveKeys = []string{
	"password", "passwd", "secret", "token", "api_key",
	"api-key", "apikey", "authorization", "credential",
	"private_key", "access_key", "ARES_LLM_API_KEY",
	"ARES_ATTACK_LLM_API_KEY", "ARES_ADMIN_PASSWORD",
	"ARES_ANALYST_PASSWORD", "jwt", "refresh_token",
	"access_token", "session_key", "auth_token",
	"client_secret", "x-api-key", "x-auth-token",
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, sk := range sensitiveKeys {
		if strings.Contains(lower, sk) {
			return true
		}
	}
	return false
}

func RedactFields(fields Fields) Fields {
	result := make(Fields, len(fields))
	for k, v := range fields {
		result[k] = redactValue(k, v)
	}
	return result
}

func redactValue(key string, v interface{}) interface{} {
	if isSensitiveKey(key) {
		return "***REDACTED***"
	}
	switch val := v.(type) {
	case string:
		if looksLikeSecret(val) {
			return "***REDACTED***"
		}
		return val
	case map[string]interface{}:
		return redactNested(val)
	case Fields:
		return RedactFields(val)
	case []interface{}:
		return redactSlice(val)
	case []map[string]interface{}:
		result := make([]map[string]interface{}, len(val))
		for i, m := range val {
			result[i] = redactNested(m)
		}
		return result
	default:
		return v
	}
}

func redactNested(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = redactValue(k, v)
	}
	return result
}

func redactSlice(s []interface{}) []interface{} {
	result := make([]interface{}, len(s))
	for i, v := range s {
		switch val := v.(type) {
		case map[string]interface{}:
			result[i] = redactNested(val)
		case Fields:
			result[i] = RedactFields(val)
		case []interface{}:
			result[i] = redactSlice(val)
		case string:
			if looksLikeSecret(val) {
				result[i] = "***REDACTED***"
			} else {
				result[i] = val
			}
		default:
			result[i] = val
		}
	}
	return result
}

var secretLikePatterns = []string{
	"sk-", "pk-", "AKIA", "eyJ", "ghp_", "gho_", "ghu_",
	"github_pat", "xoxb-", "xoxp-", "xapp-",
}

func looksLikeSecret(s string) bool {
	if len(s) < 16 {
		return false
	}
	for _, pattern := range secretLikePatterns {
		if strings.HasPrefix(s, pattern) {
			return true
		}
	}
	alphaNum := 0
	for _, r := range s {
		if ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') || r == '-' || r == '_' {
			alphaNum++
		}
	}
	return alphaNum == len(s) && len(s) >= 32
}

func GenerateTraceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		Warn(fmt.Sprintf("crypto/rand failed during trace ID generation: %v", err))
		b = make([]byte, 16)
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i * 8))
		}
	}
	return hex.EncodeToString(b)
}

func GenerateSpanID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		Warn(fmt.Sprintf("crypto/rand failed during span ID generation: %v", err))
		b = make([]byte, 8)
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i * 8))
		}
	}
	return hex.EncodeToString(b)
}

func Debug(msg string, fields ...Fields) {
	var f Fields
	if len(fields) > 0 {
		f = fields[0]
	}
	Get().Debug(msg, f)
}
func Info(msg string, fields ...Fields) {
	var f Fields
	if len(fields) > 0 {
		f = fields[0]
	}
	Get().Info(msg, f)
}
func Warn(msg string, fields ...Fields) {
	var f Fields
	if len(fields) > 0 {
		f = fields[0]
	}
	Get().Warn(msg, f)
}
func Error(msg string, fields ...Fields) {
	var f Fields
	if len(fields) > 0 {
		f = fields[0]
	}
	Get().Error(msg, f)
}
func Fatal(msg string, fields ...Fields) {
	var f Fields
	if len(fields) > 0 {
		f = fields[0]
	}
	Get().Fatal(msg, f)
}
