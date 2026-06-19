package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type EnvStore struct {
	mu        sync.RWMutex
	filepath  string
	overrides map[string]string
	cipher    cipher.AEAD
}

func NewEnvStore(filepath string) *EnvStore {
	masterKey := os.Getenv("ARES_ENVSTORE_KEY")
	var key [32]byte
	if masterKey != "" {
		hashed := sha256.Sum256([]byte(masterKey))
		copy(key[:], hashed[:])
	} else {
		if _, err := rand.Read(key[:]); err != nil {
			es := &EnvStore{
				filepath:  filepath,
				overrides: make(map[string]string),
			}
			return es
		}
	}
	es, err := newEnvStoreWithKey(filepath, key[:])
	if err != nil {
		es = &EnvStore{
			filepath:  filepath,
			overrides: make(map[string]string),
		}
	}
	return es
}

func NewEnvStoreSecure(filepath string, key []byte) (*EnvStore, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes")
	}
	return newEnvStoreWithKey(filepath, key)
}

func newEnvStoreWithKey(filepath string, key []byte) (*EnvStore, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	es := &EnvStore{
		filepath:  filepath,
		overrides: make(map[string]string),
		cipher:    gcm,
	}
	if err := es.load(); err != nil {
		return nil, err
	}
	return es, nil
}

func (es *EnvStore) GetAll() map[string]string {
	es.mu.RLock()
	defer es.mu.RUnlock()
	cpy := make(map[string]string, len(es.overrides))
	for k, v := range es.overrides {
		cpy[k] = v
	}
	return cpy
}

func (es *EnvStore) Get(key string) (string, bool) {
	es.mu.RLock()
	defer es.mu.RUnlock()
	val, ok := es.overrides[key]
	return val, ok
}

func (es *EnvStore) Set(key, value string) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.overrides[key] = value
	es.save()
}

func (es *EnvStore) SetBatch(kv map[string]string) {
	es.mu.Lock()
	defer es.mu.Unlock()
	for k, v := range kv {
		es.overrides[k] = v
	}
	es.save()
}

func (es *EnvStore) Delete(key string) {
	es.mu.Lock()
	defer es.mu.Unlock()
	delete(es.overrides, key)
	es.save()
}

func (es *EnvStore) load() error {
	if es.filepath == "" {
		return nil
	}
	data, err := os.ReadFile(es.filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if es.cipher == nil {
		var overrides map[string]string
		if err := json.Unmarshal(data, &overrides); err != nil {
			return err
		}
		es.overrides = overrides
		return nil
	}
	decrypted, err := es.decrypt(data)
	if err != nil {
		return fmt.Errorf("failed to decrypt envstore (corrupted or tampered): %w", err)
	}
	var overrides map[string]string
	if err := json.Unmarshal(decrypted, &overrides); err != nil {
		return err
	}
	es.overrides = overrides
	return nil
}

func (es *EnvStore) save() error {
	if es.filepath == "" {
		return nil
	}
	data, err := json.Marshal(es.overrides)
	if err != nil {
		return err
	}
	if es.cipher == nil {
		return os.WriteFile(es.filepath, data, 0600)
	}
	encrypted, err := es.encrypt(data)
	if err != nil {
		return err
	}
	return os.WriteFile(es.filepath, encrypted, 0600)
}

func (es *EnvStore) encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, es.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return es.cipher.Seal(nonce, nonce, data, nil), nil
}

func (es *EnvStore) decrypt(data []byte) ([]byte, error) {
	nonceSize := es.cipher.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return es.cipher.Open(nil, nonce, ciphertext, nil)
}
