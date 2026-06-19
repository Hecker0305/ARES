package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

type Manager struct {
	mu          sync.RWMutex
	certFile    string
	keyFile     string
	cert        *tls.Certificate
	certPool    *x509.CertPool
	autoRenew   bool
	renewBefore time.Duration
	lastLoaded  time.Time
	onChange    func()
}

type Config struct {
	CertFile    string
	KeyFile     string
	CACertFile  string
	AutoRenew   bool
	RenewBefore time.Duration
	MinVersion  uint16
}

func NewManager(cfg Config) (*Manager, error) {
	m := &Manager{
		certFile:    cfg.CertFile,
		keyFile:     cfg.KeyFile,
		autoRenew:   cfg.AutoRenew,
		renewBefore: cfg.RenewBefore,
	}

	if m.renewBefore == 0 {
		m.renewBefore = 24 * time.Hour
	}

	if cfg.CACertFile != "" {
		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		m.certPool = certPool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		if err := m.loadCertificate(); err != nil {
			return nil, fmt.Errorf("load certificate: %w", err)
		}
	}

	return m, nil
}

func (m *Manager) loadCertificate() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cert, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return fmt.Errorf("load key pair: %w", err)
	}

	m.cert = &cert
	m.lastLoaded = time.Now()

	logger.Info("[TLS] Certificate loaded", logger.Fields{
		"cert_file": m.certFile,
	})

	if m.onChange != nil {
		m.onChange()
	}

	return nil
}

func (m *Manager) GetCertificate() (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cert == nil {
		return nil, fmt.Errorf("no certificate loaded")
	}

	if m.autoRenew && time.Since(m.lastLoaded) > m.renewBefore {
		m.mu.RUnlock()
		if err := m.loadCertificate(); err != nil {
			m.mu.RLock()
			logger.Error(fmt.Sprintf("[TLS] Auto-renewal failed: %v", err))
			return m.cert, nil
		}
		m.mu.RLock()
	}

	return m.cert, nil
}

func (m *Manager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return m.GetCertificate()
		},
		ClientCAs:  m.certPool,
		MinVersion: tls.VersionTLS12,
	}
}

func (m *Manager) SetOnChange(fn func()) {
	m.onChange = fn
}

func (m *Manager) GetExpiryDate() (time.Time, error) {
	cert, err := m.GetCertificate()
	if err != nil {
		return time.Time{}, err
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}

	return parsedCert.NotAfter, nil
}

func (m *Manager) DaysUntilExpiry() (int, error) {
	expiry, err := m.GetExpiryDate()
	if err != nil {
		return 0, err
	}

	days := int(time.Until(expiry).Hours() / 24)
	return days, nil
}

func (m *Manager) NeedsRenewal() (bool, error) {
	days, err := m.DaysUntilExpiry()
	if err != nil {
		return false, err
	}

	return days <= int(m.renewBefore.Hours()/24), nil
}

func (m *Manager) Reload() error {
	return m.loadCertificate()
}

type ACMEConfig struct {
	Domain     string
	Email      string
	CertDir    string
	Production bool
}

func NewACMEManager(cfg ACMEConfig) (*Manager, error) {
	certFile := cfg.CertDir + "/cert.pem"
	keyFile := cfg.CertDir + "/key.pem"

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		logger.Info("[TLS] No certificate found, would obtain via ACME")
		logger.Info("[TLS] For production, use: certbot, lego, or cloud provider cert manager")
	}

	return NewManager(Config{
		CertFile:    certFile,
		KeyFile:     keyFile,
		AutoRenew:   true,
		RenewBefore: 30 * 24 * time.Hour,
	})
}

func GetMinVersionFromString(version string) uint16 {
	switch version {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}
