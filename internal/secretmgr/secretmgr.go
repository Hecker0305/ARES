package secretmgr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/secrets"
	"github.com/ares/engine/internal/security"
)

type SecretType string

const (
	SecretAPIKey     SecretType = "api_key"
	SecretAuthToken  SecretType = "auth_token"
	SecretDBPassword SecretType = "db_password"
	SecretTLSKey     SecretType = "tls_key"
	SecretOAuthToken SecretType = "oauth_token"
)

type Secret struct {
	Name        string                `json:"name"`
	Type        SecretType            `json:"type"`
	Value       security.SecretString `json:"-"`
	LastRotated time.Time             `json:"last_rotated"`
	ExpiresAt   time.Time             `json:"expires_at"`
	Provider    string                `json:"provider"`
}

type EncryptedSecret struct {
	Ciphertext  string     `json:"ciphertext"`
	Nonce       string     `json:"nonce"`
	Name        string     `json:"name"`
	Type        SecretType `json:"type"`
	LastRotated time.Time  `json:"last_rotated"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Provider    string     `json:"provider"`
}

type VaultConfig struct {
	Address string `json:"address"`
	Token   string `json:"token"`
	Path    string `json:"path"`
}

type AWSSecretsConfig struct {
	Region    string `json:"region"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

type Manager struct {
	mu             sync.RWMutex
	secrets        map[string]*Secret
	vaultCfg       *VaultConfig
	awsCfg         *AWSSecretsConfig
	rotationPolicy map[SecretType]time.Duration
	client         *http.Client
	encryptionKey  []byte
	aead           cipher.AEAD
}

func NewManager() (*Manager, error) {
	var key []byte
	if keyPath := os.Getenv("ARES_SECRETMGR_KEY_FILE"); keyPath != "" {
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read encryption key from %s: %w", keyPath, err)
		}
		key = keyData
	} else if keyHex := secrets.Get("ARES_SECRETMGR_KEY"); keyHex != "" {
		var err error
		key, err = hex.DecodeString(keyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ARES_SECRETMGR_KEY: %w", err)
		}
	}
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
		logger.Warn("[SecretMgr] Generated ephemeral encryption key — previously encrypted secrets will be undecryptable after restart. Set ARES_SECRETMGR_KEY or ARES_SECRETMGR_KEY_FILE.")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	m := &Manager{
		secrets:       make(map[string]*Secret),
		encryptionKey: key,
		aead:          aead,
		rotationPolicy: map[SecretType]time.Duration{
			SecretAPIKey:     90 * 24 * time.Hour,
			SecretAuthToken:  30 * 24 * time.Hour,
			SecretDBPassword: 60 * 24 * time.Hour,
			SecretTLSKey:     365 * 24 * time.Hour,
			SecretOAuthToken: 1 * time.Hour,
		},
		client: &http.Client{Timeout: 30 * time.Second},
	}

	if vaultAddr := os.Getenv("VAULT_ADDR"); vaultAddr != "" {
		m.vaultCfg = &VaultConfig{
			Address: vaultAddr,
			Token:   secrets.Get("VAULT_TOKEN"),
			Path:    os.Getenv("VAULT_PATH"),
		}
	}

	if awsRegion := os.Getenv("AWS_REGION"); awsRegion != "" {
		m.awsCfg = &AWSSecretsConfig{
			Region:    awsRegion,
			AccessKey: secrets.Get("AWS_ACCESS_KEY_ID"),
			SecretKey: secrets.Get("AWS_SECRET_ACCESS_KEY"),
		}
	}

	m.loadFromEnvironment()

	return m, nil
}

func NewInsecureManager() *Manager {
	logger.Warn("[SecretMgr] Using insecure manager (no encryption) - not recommended for production")
	m := &Manager{
		secrets:       make(map[string]*Secret),
		encryptionKey: nil,
		aead:          nil,
		rotationPolicy: map[SecretType]time.Duration{
			SecretAPIKey:     90 * 24 * time.Hour,
			SecretAuthToken:  30 * 24 * time.Hour,
			SecretDBPassword: 60 * 24 * time.Hour,
			SecretTLSKey:     365 * 24 * time.Hour,
			SecretOAuthToken: 1 * time.Hour,
		},
		client: &http.Client{Timeout: 30 * time.Second},
	}
	m.loadFromEnvironment()
	return m
}

func (m *Manager) loadFromEnvironment() {
	envSecrets := map[string]SecretType{
		"ARES_API_KEY":                SecretAPIKey,
		"ARES_AUTH_TOKEN":             SecretAuthToken,
		"ARES_DB_PASSWORD":            SecretDBPassword,
		"ARES_OAUTH_TOKEN":            SecretOAuthToken,
		"ARES_BOUNTY_HACKERONE_TOKEN": SecretAPIKey,
		"ARES_BOUNTY_BUGCROWD_TOKEN":  SecretAPIKey,
	}

	for envKey, secretType := range envSecrets {
		if value := os.Getenv(envKey); value != "" {
			m.secrets[envKey] = &Secret{
				Name:        envKey,
				Type:        secretType,
				Value:       security.NewSecret(value),
				LastRotated: time.Now(),
				ExpiresAt:   time.Now().Add(m.rotationPolicy[secretType]),
				Provider:    "environment",
			}
		}
	}
}

func (m *Manager) encryptValue(value string) (string, string, error) {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := m.aead.Seal(nil, nonce, []byte(value), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce), nil
}

func (m *Manager) decryptValue(ciphertextB64, nonceB64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	plaintext, err := m.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

func (m *Manager) Get(name string) (*Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	secret, ok := m.secrets[name]
	if !ok {
		return nil, fmt.Errorf("secret %q not found", name)
	}

	if time.Now().After(secret.ExpiresAt) {
		return nil, fmt.Errorf("secret %q has expired", name)
	}

	safe := *secret
	return &safe, nil
}

func (m *Manager) Set(name string, secretType SecretType, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.secrets[name] = &Secret{
		Name:        name,
		Type:        secretType,
		Value:       security.NewSecret(value),
		LastRotated: time.Now(),
		ExpiresAt:   time.Now().Add(m.rotationPolicy[secretType]),
		Provider:    "manual",
	}

	return nil
}

func (m *Manager) ExportEncrypted(name string) (*EncryptedSecret, error) {
	m.mu.RLock()
	secret, ok := m.secrets[name]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("secret %q not found", name)
	}

	encValue, nonce, err := m.encryptValue(secret.Value.Plain())
	if err != nil {
		return nil, err
	}

	return &EncryptedSecret{
		Ciphertext:  encValue,
		Nonce:       nonce,
		Name:        secret.Name,
		Type:        secret.Type,
		LastRotated: secret.LastRotated,
		ExpiresAt:   secret.ExpiresAt,
		Provider:    secret.Provider,
	}, nil
}

func (m *Manager) Rotate(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, ok := m.secrets[name]
	if !ok {
		return fmt.Errorf("secret %q not found", name)
	}

	var newValue string
	var err error

	switch secret.Provider {
	case "vault":
		newValue, err = m.rotateViaVault(name)
	case "aws":
		newValue, err = m.rotateViaAWS(name)
	default:
		newValue, err = generateNewSecret(secret.Type)
	}

	if err != nil {
		return fmt.Errorf("rotation failed: %w", err)
	}

	secret.Value = security.NewSecret(newValue)
	secret.LastRotated = time.Now()
	secret.ExpiresAt = time.Now().Add(m.rotationPolicy[secret.Type])

	logger.Info(fmt.Sprintf("[SecretMgr] Rotated secret: %s", name))
	return nil
}

func (m *Manager) RotateAll() []error {
	m.mu.RLock()
	names := make([]string, 0, len(m.secrets))
	for name := range m.secrets {
		names = append(names, name)
	}
	m.mu.RUnlock()

	var errs []error
	for _, name := range names {
		if err := m.Rotate(name); err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func (m *Manager) CheckExpiring(threshold time.Duration) []*Secret {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var expiring []*Secret
	now := time.Now()

	for _, secret := range m.secrets {
		if now.Add(threshold).After(secret.ExpiresAt) {
			safe := *secret
			expiring = append(expiring, &safe)
		}
	}

	return expiring
}

func (m *Manager) ListSecrets() []Secret {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var secrets []Secret
	for _, s := range m.secrets {
		safe := *s
		safe.Value = security.NewSecret("***")
		secrets = append(secrets, safe)
	}

	return secrets
}

func (m *Manager) rotateViaVault(name string) (string, error) {
	if m.vaultCfg == nil {
		return "", fmt.Errorf("vault not configured")
	}

	url := fmt.Sprintf("%s/v1/%s/rotate/%s", m.vaultCfg.Address, m.vaultCfg.Path, name)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", m.vaultCfg.Token)

	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("vault rotation failed: status %d (body read error: %v)", resp.StatusCode, err)
		}
		return "", fmt.Errorf("vault rotation failed: %s", string(body))
	}

	var result struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Data.Value, nil
}

func (m *Manager) rotateViaAWS(name string) (string, error) {
	if m.awsCfg == nil {
		return "", fmt.Errorf("AWS not configured")
	}

	url := fmt.Sprintf("https://secretsmanager.%s.amazonaws.com", m.awsCfg.Region)

	input := map[string]interface{}{
		"SecretId": name,
	}

	body, err := json.Marshal(input)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.RotateSecret")

	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("AWS rotation failed: status %d (body read error: %v)", resp.StatusCode, err)
		}
		return "", fmt.Errorf("AWS rotation failed: %s", string(respBody))
	}

	return generateRandomString(32)
}

func generateNewSecret(secretType SecretType) (string, error) {
	switch secretType {
	case SecretAPIKey, SecretAuthToken, SecretOAuthToken:
		return generateRandomString(32)
	case SecretDBPassword:
		return generateRandomString(24)
	case SecretTLSKey:
		return generateRandomString(64)
	default:
		return generateRandomString(32)
	}
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:length], nil
}

func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, ok := m.secrets[name]
	if !ok {
		return fmt.Errorf("secret %q not found", name)
	}

	secret.Value = security.SecretString{}
	delete(m.secrets, name)

	logger.Info(fmt.Sprintf("[SecretMgr] Securely removed secret: %s", name))
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, secret := range m.secrets {
		secret.Value = security.SecretString{}
		delete(m.secrets, name)
	}

	if m.encryptionKey != nil {
		security.ClearSensitiveData(m.encryptionKey)
		m.encryptionKey = nil
	}

	logger.Info("[SecretMgr] Manager closed, all secrets and keys wiped from memory")
	return nil
}
