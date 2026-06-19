package apikey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/auth"
	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type APIKey struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Prefix    string        `json:"prefix"`
	Hash      string        `json:"-"`
	Role      auth.UserRole `json:"role"`
	CreatedAt time.Time     `json:"created_at"`
	LastUsed  time.Time     `json:"last_used,omitempty"`
	IsActive  bool          `json:"is_active"`
}

type Manager struct {
	mu        sync.RWMutex
	keys      map[string]*APIKey
	storePath string
}

func NewManager(storePath string) *Manager {
	if storePath == "" {
		storePath = "apikeys.json"
	}
	m := &Manager{
		keys:      make(map[string]*APIKey),
		storePath: storePath,
	}
	m.load()
	return m
}

func getHMACSecret() []byte {
	secret := os.Getenv("ARES_APIKEY_HMAC_SECRET")
	if secret == "" {
		logger.Warn("[APIKey] ARES_APIKEY_HMAC_SECRET not set, using fallback (rotate immediately in production)")
		secret = "ares-apikey-hmac"
	}
	return []byte(secret)
}

func (m *Manager) Create(name string, role auth.UserRole) (*APIKey, string, error) {
	if name == "" {
		return nil, "", fmt.Errorf("name is required")
	}
	if role == "" {
		role = auth.RoleViewer
	}

	id := uuid.New()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("failed to generate key: %w", err)
	}
	key := hex.EncodeToString(raw)
	prefix := key[:8]

	mac := hmac.New(sha256.New, getHMACSecret())
	mac.Write([]byte(key))
	hash := hex.EncodeToString(mac.Sum(nil))

	k := &APIKey{
		ID:        id,
		Name:      name,
		Prefix:    prefix,
		Hash:      hash,
		Role:      role,
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	m.mu.Lock()
	m.keys[id] = k
	m.persist()
	m.mu.Unlock()

	return k, fmt.Sprintf("ares_%s_%s", prefix, key), nil
}

func (m *Manager) Validate(key string) (*APIKey, error) {
	if len(key) < 10 || !strings.HasPrefix(key, "ares_") {
		return nil, fmt.Errorf("invalid key format")
	}

	parts := strings.SplitN(key, "_", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid key format")
	}
	prefix := parts[1]
	secret := parts[2]

	mac := hmac.New(sha256.New, getHMACSecret())
	mac.Write([]byte(secret))
	hash := hex.EncodeToString(mac.Sum(nil))

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, k := range m.keys {
		if k.Prefix == prefix && k.Hash == hash {
			if !k.IsActive {
				return nil, fmt.Errorf("key is deactivated")
			}
			return k, nil
		}
	}
	return nil, fmt.Errorf("key not found")
}

func (m *Manager) List() []*APIKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*APIKey, 0, len(m.keys))
	for _, k := range m.keys {
		out = append(out, k)
	}
	return out
}

func (m *Manager) Get(id string) (*APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.keys[id]
	if !ok {
		return nil, fmt.Errorf("key %s not found", id)
	}
	return k, nil
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[id]; !ok {
		return fmt.Errorf("key %s not found", id)
	}
	delete(m.keys, id)
	return m.persist()
}

func (m *Manager) RecordUsage(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.keys[id]; ok {
		k.LastUsed = time.Now()
		m.persist()
	}
}

func (m *Manager) persist() error {
	if m.storePath == "" {
		return nil
	}
	data, err := json.MarshalIndent(m.keys, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := m.storePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	if err := os.Remove(m.storePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tmpPath, m.storePath)
}

func (m *Manager) load() {
	if m.storePath == "" {
		return
	}
	data, err := os.ReadFile(m.storePath)
	if err != nil {
		return
	}
	var loaded map[string]*APIKey
	if err := json.Unmarshal(data, &loaded); err != nil {
		return
	}
	for id, k := range loaded {
		if k != nil {
			m.keys[id] = k
		}
	}
}
