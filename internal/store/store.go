package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"golang.org/x/crypto/scrypt"
)

type PersistedSession struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type PersistedFinding struct {
	ID          string            `json:"id"`
	ScanID      string            `json:"scan_id"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Target      string            `json:"target"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Evidence    map[string]string `json:"evidence"`
	MitreTags   []string          `json:"mitre_tags"`
	CVSS        float64           `json:"cvss"`
	Confirmed   bool              `json:"confirmed"`
	Timestamp   time.Time         `json:"timestamp"`
}

type PersistedScan struct {
	ID        string             `json:"id"`
	Target    string             `json:"target"`
	StartTime time.Time          `json:"start_time"`
	Status    string             `json:"status"`
	Findings  []PersistedFinding `json:"findings"`
	Phase     string             `json:"phase"`
	Progress  float64            `json:"progress"`
	TenantID  string             `json:"tenant_id,omitempty"`
}

type WebhookEntry struct {
	ID      string `json:"id"`
	URL     string `json:"url"`
	Type    string `json:"type"`
	Events  string `json:"events"`
	Enabled bool   `json:"enabled"`
}

type Store struct {
	mu         sync.RWMutex
	dataDir    string
	scans      map[string]*PersistedScan
	findings   map[string]*PersistedFinding
	sessions   map[string]*PersistedSession
	webhooks   map[string]*WebhookEntry
	dirty      bool
	saveTicker *time.Ticker
	stopCh     chan struct{}
	encryptKey []byte
	aead       cipher.AEAD
}

func New(dataDir string) *Store {
	os.MkdirAll(dataDir, 0700)

	key := deriveEncryptionKey(dataDir)
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Warn("[Store] Failed to create cipher, running without encryption")
		block = nil
	}
	var aead cipher.AEAD
	if block != nil {
		aead, err = cipher.NewGCM(block)
		if err != nil {
			logger.Warn("[Store] Failed to create GCM, running without encryption")
			aead = nil
		}
	}

	s := &Store{
		dataDir:    dataDir,
		scans:      make(map[string]*PersistedScan),
		findings:   make(map[string]*PersistedFinding),
		sessions:   make(map[string]*PersistedSession),
		webhooks:   make(map[string]*WebhookEntry),
		stopCh:     make(chan struct{}),
		encryptKey: key,
		aead:       aead,
	}
	s.loadAll()
	s.saveTicker = time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-s.saveTicker.C:
				s.flush()
				s.cleanup()
			case <-s.stopCh:
				s.flush()
				return
			}
		}
	}()
	return s
}

func deriveEncryptionKey(dataDir string) []byte {
	envKey := os.Getenv("ARES_ENCRYPTION_KEY")
	if envKey != "" {
		decoded, err := hex.DecodeString(envKey)
		if err == nil && len(decoded) == 32 {
			return decoded
		}
		salt := []byte("ares-store-v1")
		key, err := scrypt.Key([]byte(envKey), salt, 32768, 8, 1, 32)
		if err == nil {
			return key
		}
		hash := sha256.Sum256([]byte(envKey))
		return hash[:]
	}

	// Try reading from known key file locations
	for _, dir := range []string{dataDir, ""} {
		if dir == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				continue
			}
			dir = filepath.Join(homeDir, ".ares")
		}
		keyFile := filepath.Join(dir, "encryption.key")
		if data, err := os.ReadFile(keyFile); err == nil && len(data) == 32 {
			return data
		} else if os.IsNotExist(err) {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				continue
			}
			if err := os.MkdirAll(dir, 0700); err == nil {
				if err := os.WriteFile(keyFile, key, 0600); err == nil {
					logger.Warn("[Store] Generated new encryption key at " + keyFile)
					return key
				}
			}
		}
	}

	logger.Error("[Store] Failed to persist encryption key — encrypted data will be lost on restart")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

func (s *Store) Close() {
	if s.saveTicker != nil {
		s.saveTicker.Stop()
	}
	close(s.stopCh)
}

func (s *Store) GetScan(id string) *PersistedScan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scans[id]
}

func (s *Store) DeleteScan(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.scans, id)
	s.dirty = true
}

func (s *Store) SaveFinding(f *PersistedFinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings[f.ID] = f
	s.dirty = true
}

func (s *Store) GetFinding(id string) *PersistedFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findings[id]
}

func (s *Store) ListFindings(scanID string) []*PersistedFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*PersistedFinding
	for _, f := range s.findings {
		if scanID == "" || f.ScanID == scanID {
			cp := *f
			out = append(out, &cp)
		}
	}
	return out
}

func (s *Store) SaveSession(session *PersistedSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.Token] = session
	s.dirty = true
}

func (s *Store) GetSession(token string) *PersistedSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[token]
}

func (s *Store) DeleteSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
	s.dirty = true
}

func (s *Store) SaveWebhook(entry *WebhookEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhooks[entry.ID] = entry
	s.dirty = true
}

func (s *Store) ListWebhooks() []*WebhookEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*WebhookEntry
	for _, e := range s.webhooks {
		cp := *e
		out = append(out, &cp)
	}
	return out
}

func (s *Store) DeleteWebhook(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.webhooks, id)
	s.dirty = true
}

func (s *Store) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, scan := range s.scans {
		if now.Sub(scan.StartTime) > 7*24*time.Hour {
			delete(s.scans, id)
		}
	}
	for id, f := range s.findings {
		if now.Sub(f.Timestamp) > 7*24*time.Hour {
			delete(s.findings, id)
		}
	}
	for token, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}

func (s *Store) SaveScan(scan *PersistedScan) {
	s.mu.Lock()
	s.scans[scan.ID] = scan
	s.dirty = true
	s.mu.Unlock()
}

func (s *Store) ListScans(tenantID string) []*PersistedScan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*PersistedScan
	for _, scan := range s.scans {
		if tenantID == "" || scan.TenantID == tenantID {
			cp := *scan
			cp.Findings = make([]PersistedFinding, len(scan.Findings))
			copy(cp.Findings, scan.Findings)
			out = append(out, &cp)
		}
	}
	return out
}

func (s *Store) flush() {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return
	}
	s.dirty = false
	scansCopy := make(map[string]*PersistedScan)
	for k, v := range s.scans {
		scansCopy[k] = v
	}
	findingsCopy := make(map[string]*PersistedFinding)
	for k, v := range s.findings {
		findingsCopy[k] = v
	}
	sessionsCopy := make(map[string]*PersistedSession)
	for k, v := range s.sessions {
		sessionsCopy[k] = v
	}
	webhooksCopy := make(map[string]*WebhookEntry)
	for k, v := range s.webhooks {
		webhooksCopy[k] = v
	}
	s.mu.Unlock()

	s.writeFile("scans.json", scansCopy)
	s.writeFile("findings.json", findingsCopy)
	s.writeFile("sessions.json", sessionsCopy)
	s.writeFile("webhooks.json", webhooksCopy)
}

func (s *Store) writeFile(name string, data interface{}) {
	path := filepath.Join(s.dataDir, name)
	tmpPath := path + ".tmp"
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logger.Info(fmt.Sprintf("[Store] marshal %s: %v", name, err))
		return
	}
	if err := os.WriteFile(tmpPath, b, 0600); err != nil {
		logger.Info(fmt.Sprintf("[Store] write %s: %v", tmpPath, err))
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		logger.Info(fmt.Sprintf("[Store] rename %s: %v", tmpPath, err))
	}
}

func (s *Store) loadAll() {
	for name, dest := range map[string]interface{}{
		"scans.json":    &s.scans,
		"findings.json": &s.findings,
		"sessions.json": &s.sessions,
		"webhooks.json": &s.webhooks,
	} {
		s.loadFile(name, dest)
	}
}

func (s *Store) loadFile(name string, dest interface{}) {
	path := filepath.Join(s.dataDir, name)
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Info(fmt.Sprintf("[Store] read %s: %v", name, err))
		}
		return
	}
	if err := json.Unmarshal(b, dest); err != nil {
		logger.Info(fmt.Sprintf("[Store] parse %s: %v", name, err))
	}
}
