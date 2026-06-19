package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var (
	defaultStore     *Store
	defaultStoreOnce sync.Once
)

func defaultStoreInit() {
	defaultStoreOnce.Do(func() {
		pass := os.Getenv("ARES_SECRETS_PASSPHRASE")
		if pass == "" {
			pass = "ares-default-development-only"
		}
		home, _ := os.UserHomeDir()
		path := filepath.Join(home, ".ares", "secrets.enc")
		s, err := NewStore(path, pass)
		if err != nil {
			return
		}
		defaultStore = s
	})
}

func Get(key string) string {
	defaultStoreInit()
	if defaultStore == nil {
		return os.Getenv(key)
	}
	v, ok := defaultStore.Get(key)
	if !ok {
		return os.Getenv(key)
	}
	return v
}

func Invalidate(key string) {
	defaultStoreInit()
	if defaultStore != nil {
		defaultStore.Delete(key)
		defaultStore.Save()
	}
	os.Unsetenv(key)
}

func Set(key, value string) {
	defaultStoreInit()
	if defaultStore != nil {
		defaultStore.Set(key, value)
		defaultStore.Save()
	}
	os.Setenv(key, value)
}

type Store struct {
	mu         sync.RWMutex
	passphrase []byte
	path       string
	data       map[string]string
}

func NewStore(path string, passphrase string) (*Store, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("home dir: %w", err)
		}
		path = filepath.Join(home, ".ares", "secrets.enc")
	}
	s := &Store{
		passphrase: deriveKey(passphrase),
		path:       path,
		data:       make(map[string]string),
	}
	if _, err := os.Stat(path); err == nil {
		if err := s.load(); err != nil {
			return nil, fmt.Errorf("load secrets: %w", err)
		}
	}
	return s, nil
}

func deriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

func (s *Store) Set(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
}

func (s *Store) Get(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	return v, ok
}

func (s *Store) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
}

func (s *Store) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		keys = append(keys, k)
	}
	return keys
}

func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	plaintext, err := json.Marshal(s.data)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	encrypted, err := encrypt(plaintext, s.passphrase)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	os.MkdirAll(filepath.Dir(s.path), 0700)
	if err := os.WriteFile(s.path, encrypted, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func (s *Store) load() error {
	encrypted, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	plaintext, err := decrypt(encrypted, s.passphrase)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if err := json.Unmarshal(plaintext, &s.data); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

type Loader struct {
	store *Store
}

func New() *Loader {
	defaultStoreInit()
	if defaultStore == nil {
		home, _ := os.UserHomeDir()
		s, _ := NewStore(filepath.Join(home, ".ares", "secrets.enc"), os.Getenv("ARES_SECRETS_PASSPHRASE"))
		defaultStore = s
	}
	return &Loader{store: defaultStore}
}

func (l *Loader) Get(key string) string {
	return Get(key)
}

func (l *Loader) Set(key, value string) {
	Set(key, value)
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
