package evidence

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

// EvidenceType defines the type of evidence collected
type EvidenceType string

const (
	EvidenceTypeFileContent   EvidenceType = "file_content"
	EvidenceTypeDatabaseInfo  EvidenceType = "database_info"
	EvidenceTypeXSSReflection EvidenceType = "xss_reflection"
	EvidenceTypeCommandOutput EvidenceType = "command_output"
	EvidenceTypeNetworkInfo   EvidenceType = "network_info"
	EvidenceTypeCredential    EvidenceType = "credential"
	EvidenceTypeWebShell      EvidenceType = "web_shell"
	EvidenceTypePersistence   EvidenceType = "persistence"
)

// Evidence represents a piece of collected evidence
type Evidence struct {
	ID          string       `json:"id"`
	Type        EvidenceType `json:"type"`
	Target      string       `json:"target"`
	Technique   string       `json:"technique,omitempty"`
	Payload     string       `json:"payload,omitempty"`
	Data        interface{}  `json:"data,omitempty"` // Actual evidence data
	CollectedAt time.Time    `json:"collected_at"`
	Source      string       `json:"source,omitempty"` // Tool or method that collected it
	Confidence  float64      `json:"confidence"`       // 0.0 to 1.0
	Tags        []string     `json:"tags,omitempty"`
	Description string       `json:"description,omitempty"`
}

// EvidenceManager handles collection, storage, and retrieval of evidence
type EvidenceManager struct {
	evidenceMap   map[string]*Evidence
	mu            sync.RWMutex
	storagePath   string
	encryptionKey [32]byte
	persistSem    chan struct{}
	stopCh        chan struct{}
}

// NewEvidenceManager creates a new evidence manager
func NewEvidenceManager(storagePath string) *EvidenceManager {
	if storagePath == "" {
		storagePath = "./evidence"
	}

	// Create storage directory if it doesn't exist
	os.MkdirAll(storagePath, 0700)

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		logger.Error(fmt.Sprintf("[Evidence] FATAL: failed to generate encryption key: %v", err))
		return nil
	}
	em := &EvidenceManager{
		evidenceMap:   make(map[string]*Evidence),
		storagePath:   storagePath,
		encryptionKey: key,
		persistSem:    make(chan struct{}, 10),
		stopCh:        make(chan struct{}),
	}
	go em.cleanupLoop()
	return em
}

func (em *EvidenceManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-em.stopCh:
			return
		case <-ticker.C:
			em.cleanup()
		}
	}
}

func (em *EvidenceManager) cleanup() {
	em.mu.Lock()
	defer em.mu.Unlock()
	cutoff := time.Now().Add(-24 * time.Hour)
	for id, ev := range em.evidenceMap {
		if ev.CollectedAt.Before(cutoff) {
			delete(em.evidenceMap, id)
		}
	}
}

func (em *EvidenceManager) Close() {
	close(em.stopCh)
}

// CollectEvidence adds new evidence to the manager
func (em *EvidenceManager) CollectEvidence(ev *Evidence) string {
	em.mu.Lock()
	defer em.mu.Unlock()

	// Generate ID if not provided
	if ev.ID == "" {
		// Create ID based on hash of content
		dataBytes, _ := json.Marshal(ev.Data)
		hash := sha256.Sum256(append([]byte(string(ev.Type)+ev.Target), dataBytes...))
		ev.ID = fmt.Sprintf("%x", hash)[:16]
	}

	// Set timestamp if not provided
	if ev.CollectedAt.IsZero() {
		ev.CollectedAt = time.Now()
	}

	// Store in memory
	em.evidenceMap[ev.ID] = ev

	// Persist to disk with bounded concurrency
	select {
	case em.persistSem <- struct{}{}:
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error(fmt.Sprintf("[Evidence] persist panic: %v", r))
				}
				<-em.persistSem
			}()
			em.persistEvidence(ev)
		}()
	default:
		logger.Warn(fmt.Sprintf("[Evidence] persist queue full, dropping evidence %s", ev.ID))
	}

	return ev.ID
}

// GetEvidence retrieves evidence by ID
func (em *EvidenceManager) GetEvidence(id string) (*Evidence, bool) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	ev, exists := em.evidenceMap[id]
	return ev, exists
}

// ListEvidence returns all evidence, optionally filtered by type
func (em *EvidenceManager) ListEvidence(evType EvidenceType) []*Evidence {
	em.mu.RLock()
	defer em.mu.RUnlock()

	var result []*Evidence
	for _, ev := range em.evidenceMap {
		if evType == "" || ev.Type == evType {
			result = append(result, ev)
		}
	}

	return result
}

// DeleteEvidence removes evidence by ID
func (em *EvidenceManager) DeleteEvidence(id string) bool {
	em.mu.Lock()
	defer em.mu.Unlock()

	if _, exists := em.evidenceMap[id]; exists {
		delete(em.evidenceMap, id)
		// Delete from disk
		os.Remove(filepath.Join(em.storagePath, id+".json"))
		return true
	}
	return false
}

func (em *EvidenceManager) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(em.encryptionKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (em *EvidenceManager) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(em.encryptionKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// persistEvidence saves evidence to disk
func (em *EvidenceManager) persistEvidence(ev *Evidence) {
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		logger.Error(fmt.Sprintf("[Evidence] failed to marshal evidence %s: %v", ev.ID, err))
		return
	}

	encrypted, err := em.encrypt(data)
	if err != nil {
		logger.Error(fmt.Sprintf("[Evidence] failed to encrypt evidence %s: %v", ev.ID, err))
		return
	}

	filename := filepath.Join(em.storagePath, ev.ID+".json")
	err = os.WriteFile(filename, encrypted, 0600)
	if err != nil {
		logger.Error(fmt.Sprintf("[Evidence] failed to write evidence %s: %v", ev.ID, err))
		return
	}
}

// loadEvidenceFromDisk loads all evidence from storage directory
func (em *EvidenceManager) loadEvidenceFromDisk() error {
	files, err := filepath.Glob(filepath.Join(em.storagePath, "*.json"))
	if err != nil {
		return err
	}

	em.mu.Lock()
	defer em.mu.Unlock()

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			logger.Error(fmt.Sprintf("[Evidence] failed to read evidence file %s: %v", file, err))
			continue
		}

		decrypted, err := em.decrypt(data)
		if err != nil {
			logger.Error(fmt.Sprintf("[Evidence] failed to decrypt evidence file %s: %v", file, err))
			continue
		}

		var ev Evidence
		if err := json.Unmarshal(decrypted, &ev); err != nil {
			logger.Error(fmt.Sprintf("[Evidence] failed to unmarshal evidence file %s: %v", file, err))
			continue
		}

		em.evidenceMap[ev.ID] = &ev
	}

	return nil
}

// GetEvidenceSummary returns a summary of collected evidence
func (em *EvidenceManager) GetEvidenceSummary() map[string]interface{} {
	em.mu.RLock()
	defer em.mu.RUnlock()

	summary := make(map[string]interface{})
	typeCounts := make(map[string]int)

	for _, ev := range em.evidenceMap {
		typeCounts[string(ev.Type)]++
	}

	summary["total_evidence"] = len(em.evidenceMap)
	summary["type_counts"] = typeCounts
	summary["evidence_ids"] = func() []string {
		ids := make([]string, 0, len(em.evidenceMap))
		for id := range em.evidenceMap {
			ids = append(ids, id)
		}
		return ids
	}()

	return summary
}

func sanitizeEvidence(ev *Evidence) *Evidence {
	if ev == nil {
		return nil
	}
	sanitized := *ev
	if sanitized.Payload != "" && len(sanitized.Payload) > 20 {
		sanitized.Payload = sanitized.Payload[:20] + "...[redacted]"
	}
	if sanitized.Description != "" {
		desc := sanitized.Description
		for _, pat := range []string{"password", "secret", "token", "api_key", "authorization"} {
			desc = strings.ReplaceAll(desc, pat, "[REDACTED]")
		}
		sanitized.Description = desc
	}
	return &sanitized
}

func ExportEvidence(ev *Evidence) ([]byte, error) {
	if ev == nil {
		return nil, fmt.Errorf("evidence is nil")
	}
	return json.Marshal(ev)
}

func ImportEvidence(data []byte) (*Evidence, error) {
	var ev Evidence
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, fmt.Errorf("unmarshal evidence: %w", err)
	}
	if ev.ID == "" {
		return nil, fmt.Errorf("evidence missing ID")
	}
	return &ev, nil
}

func SaveEvidenceToFile(dir string, ev *Evidence, encKey []byte) error {
	if ev == nil {
		return fmt.Errorf("evidence is nil")
	}
	os.MkdirAll(dir, 0700)
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}
	path := filepath.Join(dir, ev.ID+".json")
	if encKey != nil {
		block, err := aes.NewCipher(encKey[:32])
		if err != nil {
			return err
		}
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		data = aesGCM.Seal(nonce, nonce, data, nil)
	}
	return os.WriteFile(path, data, 0600)
}

func LoadEvidenceFromFile(path string) (*Evidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ev Evidence
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, fmt.Errorf("unmarshal evidence from %s: %w", path, err)
	}
	return &ev, nil
}
