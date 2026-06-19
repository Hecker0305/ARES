package evidence

import (
	"github.com/ares/engine/internal/uuid"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type EvidenceRecord struct {
	ID           string          `json:"id"`
	FindingID    string          `json:"finding_id"`
	ContentHash  string          `json:"content_hash"`
	Content      json.RawMessage `json:"content,omitempty"`
	SigningKeyID string          `json:"signing_key_id"`
	Signature    string          `json:"signature"`
	Timestamp    time.Time       `json:"timestamp"`
	PreviousID   string          `json:"previous_id,omitempty"`
	ChainRoot    string          `json:"chain_root,omitempty"`
	CreatedBy    string          `json:"created_by"`
	Action       string          `json:"action"`
}

type ChainOfCustodyEntry struct {
	ID           string    `json:"id"`
	EvidenceID   string    `json:"evidence_id"`
	Action       string    `json:"action"`
	PerformedBy  string    `json:"performed_by"`
	Timestamp    time.Time `json:"timestamp"`
	Notes        string    `json:"notes,omitempty"`
	PreviousHash string    `json:"previous_hash"`
	Hash         string    `json:"hash"`
}

type EvidenceSigner struct {
	mu         sync.RWMutex
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	keyID      string
	records    []EvidenceRecord
	chain      []ChainOfCustodyEntry
	auditLog   []ImmutableLogEntry
}

type ImmutableLogEntry struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	Level        string    `json:"level"`
	Message      string    `json:"message"`
	PreviousHash string    `json:"previous_hash"`
	Hash         string    `json:"hash"`
	Data         string    `json:"data,omitempty"`
}

func New() *EvidenceSigner {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate ed25519 key: %v", err))
	}

	keyID := fmt.Sprintf("key-%d", time.Now().Unix())
	return &EvidenceSigner{
		publicKey:  pub,
		privateKey: priv,
		keyID:      keyID,
	}
}

func (es *EvidenceSigner) PublicKey() ed25519.PublicKey {
	return es.publicKey
}

func (es *EvidenceSigner) KeyID() string {
	return es.keyID
}

func (es *EvidenceSigner) SignEvidence(findingID string, content json.RawMessage, createdBy string) (*EvidenceRecord, error) {
	contentHash := sha256.Sum256(content)
	hashHex := hex.EncodeToString(contentHash[:])

	record := EvidenceRecord{
		ID:           uuid.New(),
		FindingID:    findingID,
		ContentHash:  hashHex,
		Content:      content,
		SigningKeyID: es.keyID,
		Timestamp:    time.Now(),
		CreatedBy:    createdBy,
		Action:       "create",
	}

	es.mu.RLock()
	if len(es.records) > 0 {
		record.PreviousID = es.records[len(es.records)-1].ID
		record.ChainRoot = es.records[0].ID
	}
	es.mu.RUnlock()

	sigInput := es.serializeForSigning(record)
	sig := ed25519.Sign(es.privateKey, sigInput)
	record.Signature = hex.EncodeToString(sig)

	es.mu.Lock()
	es.records = append(es.records, record)
	es.mu.Unlock()

	es.addChainEntry(record.ID, "created", createdBy, "Evidence record created")

	return &record, nil
}

func (es *EvidenceSigner) VerifyEvidence(record EvidenceRecord) bool {
	sigInput := es.serializeForSigning(record)
	sig, err := hex.DecodeString(record.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(es.publicKey, sigInput, sig)
}

func (es *EvidenceSigner) VerifyChain() bool {
	es.mu.RLock()
	defer es.mu.RUnlock()

	for i, record := range es.records {
		if !es.VerifyEvidence(record) {
			return false
		}
		if i > 0 {
			if record.PreviousID != es.records[i-1].ID {
				return false
			}
		}
	}

	return true
}

func (es *EvidenceSigner) serializeForSigning(record EvidenceRecord) []byte {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		record.ID,
		record.FindingID,
		record.ContentHash,
		record.Timestamp.Format(time.RFC3339Nano),
		record.PreviousID,
		record.CreatedBy,
		record.Action,
	)
	return []byte(data)
}

func (es *EvidenceSigner) addChainEntry(evidenceID, action, performedBy, notes string) {
	var prevHash string
	es.mu.RLock()
	if len(es.chain) > 0 {
		prevHash = es.chain[len(es.chain)-1].Hash
	}
	es.mu.RUnlock()

	entry := ChainOfCustodyEntry{
		ID:           uuid.New(),
		EvidenceID:   evidenceID,
		Action:       action,
		PerformedBy:  performedBy,
		Timestamp:    time.Now(),
		Notes:        notes,
		PreviousHash: prevHash,
	}

	hashInput := fmt.Sprintf("%s|%s|%s|%s|%s", entry.ID, entry.EvidenceID, entry.Action, entry.Timestamp.String(), entry.PreviousHash)
	h := sha256.Sum256([]byte(hashInput))
	entry.Hash = hex.EncodeToString(h[:])

	es.mu.Lock()
	es.chain = append(es.chain, entry)
	es.mu.Unlock()
}

func (es *EvidenceSigner) AddChainEntry(evidenceID, action, performedBy, notes string) {
	es.addChainEntry(evidenceID, action, performedBy, notes)
}

func (es *EvidenceSigner) GetChain() []ChainOfCustodyEntry {
	es.mu.RLock()
	defer es.mu.RUnlock()
	result := make([]ChainOfCustodyEntry, len(es.chain))
	copy(result, es.chain)
	return result
}

func (es *EvidenceSigner) VerifyChainIntegrity() bool {
	es.mu.RLock()
	defer es.mu.RUnlock()

	for i, entry := range es.chain {
		hashInput := fmt.Sprintf("%s|%s|%s|%s|%s", entry.ID, entry.EvidenceID, entry.Action, entry.Timestamp.String(), entry.PreviousHash)
		h := sha256.Sum256([]byte(hashInput))
		expectedHash := hex.EncodeToString(h[:])
		if entry.Hash != expectedHash {
			return false
		}
		if i > 0 && entry.PreviousHash != es.chain[i-1].Hash {
			return false
		}
	}

	return true
}

func (es *EvidenceSigner) AppendImmutableLog(level, message, data string) ImmutableLogEntry {
	var previousHash string
	es.mu.RLock()
	if len(es.auditLog) > 0 {
		previousHash = es.auditLog[len(es.auditLog)-1].Hash
	}
	es.mu.RUnlock()

	entry := ImmutableLogEntry{
		ID:           uuid.New(),
		Timestamp:    time.Now(),
		Level:        level,
		Message:      message,
		PreviousHash: previousHash,
		Data:         data,
	}

	hashInput := fmt.Sprintf("%s|%s|%s|%s|%s|%s", entry.ID, entry.Timestamp.String(), entry.Level, entry.Message, entry.PreviousHash, entry.Data)
	h := sha256.Sum256([]byte(hashInput))
	entry.Hash = hex.EncodeToString(h[:])

	es.mu.Lock()
	es.auditLog = append(es.auditLog, entry)
	es.mu.Unlock()

	return entry
}

func (es *EvidenceSigner) GetImmutableLog() []ImmutableLogEntry {
	es.mu.RLock()
	defer es.mu.RUnlock()
	result := make([]ImmutableLogEntry, len(es.auditLog))
	copy(result, es.auditLog)
	return result
}

func (es *EvidenceSigner) VerifyImmutableLog() bool {
	es.mu.RLock()
	defer es.mu.RUnlock()

	for i, entry := range es.auditLog {
		hashInput := fmt.Sprintf("%s|%s|%s|%s|%s|%s", entry.ID, entry.Timestamp.String(), entry.Level, entry.Message, entry.PreviousHash, entry.Data)
		h := sha256.Sum256([]byte(hashInput))
		expectedHash := hex.EncodeToString(h[:])
		if entry.Hash != expectedHash {
			return false
		}
		if i > 0 && entry.PreviousHash != es.auditLog[i-1].Hash {
			return false
		}
	}

	return true
}

func (es *EvidenceSigner) DetectTampering() []string {
	var issues []string

	if !es.VerifyChain() {
		issues = append(issues, "evidence chain integrity check failed")
	}

	if !es.VerifyChainIntegrity() {
		issues = append(issues, "chain of custody integrity check failed")
	}

	if !es.VerifyImmutableLog() {
		issues = append(issues, "immutable audit log integrity check failed")
	}

	return issues
}
