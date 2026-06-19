package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type EnterpriseConfig struct {
	HTTP     HTTPConfig
	GRPC     GRPCConfig
	Daemon   DaemonConfig
	Storage  StorageConfig
	Security SecurityConfig
	Logging  LoggingConfig
}

type HTTPConfig struct {
	Addr            string
	TLSEnabled      bool
	CertFile        string
	KeyFile         string
	RateLimit       int
	RateLimitBurst  int
	TrustedProxies  []string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

type GRPCConfig struct {
	Port     int
	CertFile string
	KeyFile  string
}

type DaemonConfig struct {
	PythonPath  string
	MaxRetries  int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

type StorageConfig struct {
	DataDir string
}

type SecurityConfig struct {
	JWTSecret        string
	SessionKey       string
	OIDCProvider     string
	OIDCClientID     string
	OIDCClientSecret string
	AirgapMode       bool
	AllowedBinaries  []string
}

type LoggingConfig struct {
	Level  string
	Format string
	Output string
}

func LoadEnterprise() *EnterpriseConfig {
	return &EnterpriseConfig{
		HTTP: HTTPConfig{
			Addr:            envOrDefault("ARES_HTTP_ADDR", ":8080"),
			TLSEnabled:      envBool("ARES_HTTP_TLS_ENABLED", false),
			CertFile:        envOrDefault("ARES_HTTP_CERT", ""),
			KeyFile:         envOrDefault("ARES_HTTP_KEY", ""),
			RateLimit:       envInt("ARES_HTTP_RATE_LIMIT", 100),
			RateLimitBurst:  envInt("ARES_HTTP_RATE_BURST", 200),
			TrustedProxies:  envList("ARES_TRUSTED_PROXIES"),
			ReadTimeout:     envDuration("ARES_HTTP_READ_TIMEOUT", 30*time.Second),
			WriteTimeout:    envDuration("ARES_HTTP_WRITE_TIMEOUT", 30*time.Second),
			ShutdownTimeout: envDuration("ARES_HTTP_SHUTDOWN_TIMEOUT", 10*time.Second),
		},
		GRPC: GRPCConfig{
			Port:     envInt("ARES_GRPC_PORT", 8443),
			CertFile: envOrDefault("ARES_GRPC_CERT", filepath.Join("certs", "grpc-server.crt")),
			KeyFile:  envOrDefault("ARES_GRPC_KEY", filepath.Join("certs", "grpc-server.key")),
		},
		Daemon: DaemonConfig{
			PythonPath:  envOrDefault("ARES_PYTHON", "python3"),
			MaxRetries:  envInt("ARES_DAEMON_MAX_RETRIES", 3),
			BaseBackoff: envDuration("ARES_DAEMON_BASE_BACKOFF", 200*time.Millisecond),
			MaxBackoff:  envDuration("ARES_DAEMON_MAX_BACKOFF", 10*time.Second),
		},
		Storage: StorageConfig{
			DataDir: envOrDefault("ARES_DATA_DIR", "./data"),
		},
		Security: SecurityConfig{
			JWTSecret:        envOrDefault("ARES_JWT_SECRET", "change-me-in-production"),
			SessionKey:       envOrDefault("ARES_SESSION_KEY", "change-me-in-production"),
			OIDCProvider:     envOrDefault("ARES_OIDC_PROVIDER", ""),
			OIDCClientID:     envOrDefault("ARES_OIDC_CLIENT_ID", ""),
			OIDCClientSecret: envOrDefault("ARES_OIDC_CLIENT_SECRET", ""),
			AirgapMode:       envBool("ARES_AIRGAP_MODE", false),
			AllowedBinaries:  envList("ARES_ALLOWED_BINARIES"),
		},
		Logging: LoggingConfig{
			Level:  envOrDefault("ARES_LOG_LEVEL", "info"),
			Format: envOrDefault("ARES_LOG_FORMAT", "json"),
			Output: envOrDefault("ARES_LOG_OUTPUT", "stdout"),
		},
	}
}

func (c *EnterpriseConfig) String() string {
	return strings.Join([]string{
		"Enterprise{HTTP=" + c.HTTP.Addr,
		"GRPC=:" + strconv.Itoa(c.GRPC.Port),
		"Daemon=" + c.Daemon.PythonPath,
		"Storage=" + c.Storage.DataDir + "}",
	}, " ")
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		switch strings.ToLower(v) {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envList(key string) []string {
	if v := os.Getenv(key); v != "" {
		parts := strings.Split(v, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	}
	return nil
}
