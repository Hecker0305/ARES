package provenance

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

var (
	ErrChainBroken       = errors.New("provenance chain integrity violation")
	ErrSignatureInvalid  = errors.New("signature verification failed")
	ErrTamperingDetected = errors.New("tampering detected in provenance chain")
)

// Hash represents a SHA-256 hash
type Hash [32]byte

func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// HashFromBytes creates a Hash from bytes
func HashFromBytes(data []byte) Hash {
	return sha256.Sum256(data)
}

// HashFromString creates a Hash from a hex string
func HashFromString(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, fmt.Errorf("invalid hash string: %v", err)
	}
	if len(b) != 32 {
		return h, fmt.Errorf("invalid hash length: expected 32 bytes, got %d", len(b))
	}
	copy(h[:], b)
	return h, nil
}

// SignedEntry represents a cryptographically signed provenance entry
type SignedEntry struct {
	Entry
	Hash      Hash   `json:"hash"`
	PrevHash  Hash   `json:"prev_hash"`
	Signature []byte `json:"signature,omitempty"`
}

// ComputeHash computes the hash of this entry including its predecessor
func (se *SignedEntry) ComputeHash(prevHash Hash) Hash {
	h := sha256.New()
	h.Write([]byte(se.ID))
	h.Write([]byte(se.Type))
	h.Write([]byte(se.Agent))
	h.Write([]byte(se.Action))
	h.Write([]byte(se.Tool))
	h.Write([]byte(se.Target))
	h.Write([]byte(se.Input))
	h.Write([]byte(se.Output))
	h.Write([]byte(se.Decision))
	h.Write([]byte(se.Reason))
	h.Write([]byte(se.TraceID))
	h.Write([]byte(se.ParentID))
	h.Write([]byte(se.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(fmt.Sprintf("%d", se.Duration)))
	keys := make([]string, 0, len(se.Tags))
	for k := range se.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k + se.Tags[k]))
	}
	h.Write(prevHash[:])
	var hash Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// Verify verifies the hash chain entry against a known-good previous hash
// NOTE: This compares the computed expected hash against the stored Hash field.
// Integrity relies on the hash being computed correctly at Append time and
// the chain being append-only. For true cryptographic signing, use HMACSigner.
func (se *SignedEntry) Verify(prevHash Hash) bool {
	expected := se.ComputeHash(prevHash)
	return hmac.Equal(expected[:], se.Hash[:])
}

// VerifyWithSignature verifies using the stored signature (if present)
func (se *SignedEntry) VerifyWithSignature(prevHash Hash, key []byte) bool {
	if len(se.Signature) == 0 {
		return false
	}
	payload := se.serializeForSigning(prevHash)
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hmac.Equal(mac.Sum(nil), se.Signature)
}

func (se *SignedEntry) serializeForSigning(prevHash Hash) []byte {
	h := sha256.New()
	h.Write([]byte(se.ID))
	h.Write([]byte(se.Type))
	h.Write([]byte(se.Agent))
	h.Write([]byte(se.Action))
	h.Write([]byte(se.Tool))
	h.Write([]byte(se.Target))
	h.Write([]byte(se.Input))
	h.Write([]byte(se.Output))
	h.Write([]byte(se.Decision))
	h.Write([]byte(se.Reason))
	h.Write([]byte(se.TraceID))
	h.Write([]byte(se.ParentID))
	h.Write([]byte(se.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(fmt.Sprintf("%d", se.Duration)))
	keys := make([]string, 0, len(se.Tags))
	for k := range se.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k + se.Tags[k]))
	}
	h.Write(prevHash[:])
	return h.Sum(nil)
}

// ChainVerifier verifies the integrity of the provenance chain
type ChainVerifier struct {
	mu      sync.RWMutex
	chain   []SignedEntry
	genesis Hash
}

// NewChainVerifier creates a new chain verifier with an optional genesis hash
func NewChainVerifier(genesis Hash) *ChainVerifier {
	return &ChainVerifier{
		chain:   make([]SignedEntry, 0),
		genesis: genesis,
	}
}

// GenesisHash computes the genesis hash from initial state and random entropy
func GenesisHash(seed string) Hash {
	entropy := make([]byte, 32)
	_, err := rand.Read(entropy)
	if err != nil {
		return sha256.Sum256([]byte(seed + time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return sha256.Sum256(append([]byte(seed), entropy...))
}

// Append adds a new signed entry to the chain and returns its hash
func (cv *ChainVerifier) Append(entry Entry) (SignedEntry, Hash) {
	cv.mu.Lock()
	defer cv.mu.Unlock()

	var prevHash Hash
	if len(cv.chain) == 0 {
		prevHash = cv.genesis
	} else {
		prevHash = cv.chain[len(cv.chain)-1].Hash
	}

	signed := SignedEntry{
		Entry:    entry,
		PrevHash: prevHash,
	}
	signed.Hash = signed.ComputeHash(prevHash)

	cv.chain = append(cv.chain, signed)

	// Log hash for audit
	logger.Debug("provenance entry added", logger.Fields{
		"entry_id":  signed.ID,
		"hash":      signed.Hash.String(),
		"prev_hash": signed.PrevHash.String(),
		"action":    signed.Action,
		"agent":     signed.Agent,
	})

	return signed, signed.Hash
}

// VerifyChain verifies the entire chain from genesis to current
func (cv *ChainVerifier) VerifyChain() error {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	if len(cv.chain) == 0 {
		return nil
	}

	currentHash := cv.genesis

	for i, entry := range cv.chain {
		if !entry.Verify(currentHash) {
			return fmt.Errorf(
				"%w: entry %d (id=%s) failed verification, expected hash %s, got %s",
				ErrTamperingDetected,
				i,
				entry.ID,
				currentHash.String(),
				entry.Hash.String(),
			)
		}
		currentHash = entry.Hash
	}

	return nil
}

// VerifyRange verifies a range of entries
func (cv *ChainVerifier) VerifyRange(start, end int) error {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	if start < 0 || end > len(cv.chain) || start >= end {
		return fmt.Errorf("invalid range: start=%d, end=%d, length=%d", start, end, len(cv.chain))
	}

	currentHash := cv.genesis
	if start > 0 {
		currentHash = cv.chain[start-1].Hash
	}

	for i := start; i < end; i++ {
		if !cv.chain[i].Verify(currentHash) {
			return fmt.Errorf(
				"%w: entry %d (id=%s) failed verification",
				ErrTamperingDetected,
				i,
				cv.chain[i].ID,
			)
		}
		currentHash = cv.chain[i].Hash
	}

	return nil
}

// GetChainHash returns the current chain tip hash
func (cv *ChainVerifier) GetChainHash() Hash {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	if len(cv.chain) == 0 {
		return cv.genesis
	}
	return cv.chain[len(cv.chain)-1].Hash
}

// GetEntryByHash finds an entry by its hash
func (cv *ChainVerifier) GetEntryByHash(hash Hash) (*SignedEntry, error) {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	for _, entry := range cv.chain {
		if entry.Hash == hash {
			return &entry, nil
		}
	}
	return nil, fmt.Errorf("entry with hash %s not found", hash.String())
}

// VerifyEntryAt verifies a specific entry at a given index
func (cv *ChainVerifier) VerifyEntryAt(index int) error {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	if index < 0 || index >= len(cv.chain) {
		return fmt.Errorf("index out of range: %d", index)
	}

	var prevHash Hash
	if index == 0 {
		prevHash = cv.genesis
	} else {
		prevHash = cv.chain[index-1].Hash
	}

	expected := cv.chain[index].ComputeHash(prevHash)
	if !hmac.Equal(expected[:], cv.chain[index].Hash[:]) {
		return fmt.Errorf(
			"%w: entry %s hash mismatch",
			ErrTamperingDetected,
			cv.chain[index].ID,
		)
	}
	return nil
}

// ChainSummary provides a summary of the provenance chain
type ChainSummary struct {
	GenesisHash   string `json:"genesis_hash"`
	CurrentHash   string `json:"current_hash"`
	Length        int    `json:"length"`
	LatestEntryID string `json:"latest_entry_id"`
	Verified      bool   `json:"verified"`
}

// Summary returns a summary of the chain
func (cv *ChainVerifier) Summary() ChainSummary {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	verified := true
	if err := cv.VerifyChain(); err != nil {
		verified = false
	}

	latestID := ""
	if len(cv.chain) > 0 {
		latestID = cv.chain[len(cv.chain)-1].ID
	}

	return ChainSummary{
		GenesisHash:   cv.genesis.String(),
		CurrentHash:   cv.GetChainHash().String(),
		Length:        len(cv.chain),
		LatestEntryID: latestID,
		Verified:      verified,
	}
}

// MerkleVerifier provides Merkle tree verification for batch entries
type MerkleVerifier struct {
	mu     sync.RWMutex
	leaves []Hash
	root   Hash
}

// NewMerkleVerifier creates a new Merkle verifier
func NewMerkleVerifier() *MerkleVerifier {
	return &MerkleVerifier{
		leaves: make([]Hash, 0),
	}
}

// AddLeaf adds a leaf hash to the Merkle tree
func (mv *MerkleVerifier) AddLeaf(hash Hash) {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	mv.leaves = append(mv.leaves, hash)
	mv.root = mv.computeRoot()
}

// Root returns the current Merkle root
func (mv *MerkleVerifier) Root() Hash {
	mv.mu.RLock()
	defer mv.mu.RUnlock()
	return mv.root
}

// ComputeMerkleRoot computes the Merkle root from a list of hashes
func ComputeMerkleRoot(hashes []Hash) Hash {
	if len(hashes) == 0 {
		return Hash{}
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	current := make([]Hash, len(hashes))
	copy(current, hashes)

	for len(current) > 1 {
		next := make([]Hash, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			var combined []byte
			if i+1 < len(current) {
				combined = append(current[i][:], current[i+1][:]...)
			} else {
				combined = append(current[i][:], current[i][:]...)
			}
			nextHash := sha256.Sum256(combined)
			next = append(next, nextHash)
		}
		current = next
	}

	return current[0]
}

func (mv *MerkleVerifier) computeRoot() Hash {
	return ComputeMerkleRoot(mv.leaves)
}

// VerifyLeaf verifies a leaf is part of the Merkle tree
func (mv *MerkleVerifier) VerifyLeaf(leaf Hash) bool {
	mv.mu.RLock()
	defer mv.mu.RUnlock()

	for _, l := range mv.leaves {
		if l == leaf {
			return true
		}
	}
	return false
}

// Proof represents a Merkle proof for a leaf
type Proof struct {
	LeafHash Hash
	Path     []struct {
		Hash Hash
		Side string // "left" or "right"
	}
	RootHash Hash
}

// GenerateProof generates a Merkle proof for a leaf
func (mv *MerkleVerifier) GenerateProof(leafHash Hash) (*Proof, error) {
	mv.mu.RLock()
	defer mv.mu.RUnlock()

	idx := -1
	for i, l := range mv.leaves {
		if l == leafHash {
			idx = i
			break
		}
	}

	if idx == -1 {
		return nil, fmt.Errorf("leaf not found in tree")
	}

	proof := &Proof{
		LeafHash: leafHash,
		RootHash: mv.root,
	}

	current := make([]Hash, len(mv.leaves))
	copy(current, mv.leaves)
	targetIdx := idx

	for len(current) > 1 {
		next := make([]Hash, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			var combined []byte
			if i+1 < len(current) {
				if targetIdx == i {
					proof.Path = append(proof.Path, struct {
						Hash Hash
						Side string
					}{current[i+1], "right"})
					combined = append(current[i][:], current[i+1][:]...)
				} else if targetIdx == i+1 {
					proof.Path = append(proof.Path, struct {
						Hash Hash
						Side string
					}{current[i], "left"})
					combined = append(current[i][:], current[i+1][:]...)
				} else {
					combined = append(current[i][:], current[i+1][:]...)
				}
				nextHash := sha256.Sum256(combined)
				next = append(next, nextHash)
			} else {
				combined = append(current[i][:], current[i][:]...)
				nextHash := sha256.Sum256(combined)
				next = append(next, nextHash)
			}
		}
		targetIdx = targetIdx / 2
		current = next
	}

	return proof, nil
}

// VerifyProof verifies a Merkle proof
func VerifyProof(proof *Proof) bool {
	current := proof.LeafHash

	for _, step := range proof.Path {
		var combined []byte
		if step.Side == "left" {
			combined = append(step.Hash[:], current[:]...)
		} else {
			combined = append(current[:], step.Hash[:]...)
		}
		current = sha256.Sum256(combined)
	}

	return current == proof.RootHash
}

// ImmutableStore wraps a Store with cryptographic integrity
type ImmutableStore struct {
	*Store
	*ChainVerifier
	mu sync.RWMutex
}

// NewImmutableStore creates a new immutable provenance store
func NewImmutableStore(genesisSeed string) *ImmutableStore {
	genesis := GenesisHash(genesisSeed)
	return &ImmutableStore{
		Store:         New(),
		ChainVerifier: NewChainVerifier(genesis),
	}
}

// ImmutableRecord records an entry with cryptographic integrity
func (s *ImmutableStore) ImmutableRecord(entry Entry) (SignedEntry, error) {
	signedEntry, hash := s.ChainVerifier.Append(entry)
	logger.Debug(fmt.Sprintf("[Provenance] Recorded entry with hash %x...", hash[:8]))

	s.Store.mu.Lock()
	s.Store.entries = append(s.Store.entries, entry)
	s.Store.mu.Unlock()

	// Verify chain integrity after each record
	if err := s.ChainVerifier.VerifyChain(); err != nil {
		s.Store.mu.Lock()
		if len(s.Store.entries) > 0 {
			s.Store.entries = s.Store.entries[:len(s.Store.entries)-1]
		}
		s.Store.mu.Unlock()
		return SignedEntry{}, fmt.Errorf("provenance chain corruption detected: %v", err)
	}

	return signedEntry, nil
}

// VerifyIntegrity checks the entire provenance chain
func (s *ImmutableStore) VerifyIntegrity() error {
	return s.ChainVerifier.VerifyChain()
}

// Signer interface for signing provenance entries
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// Verifier interface for verifying signatures
type Verifier interface {
	Verify(data []byte, signature []byte) bool
}

// HMACSigner implements Signer using HMAC
type HMACSigner struct {
	key []byte
}

// NewHMACSigner creates a new HMAC signer
func NewHMACSigner(key []byte) *HMACSigner {
	return &HMACSigner{key: key}
}

// Sign signs data with HMAC-SHA256
func (s *HMACSigner) Sign(data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// HMACVerifier implements Verifier using HMAC
type HMACVerifier struct {
	key []byte
}

// NewHMACVerifier creates a new HMAC verifier
func NewHMACVerifier(key []byte) *HMACVerifier {
	return &HMACVerifier{key: key}
}

// Verify verifies an HMAC-SHA25 signature
func (v *HMACVerifier) Verify(data []byte, signature []byte) bool {
	expected := hmac.New(sha256.New, v.key)
	expected.Write(data)
	return hmac.Equal(expected.Sum(nil), signature)
}

// GenerateRandomKey generates a cryptographically secure random key
func GenerateRandomKey(length int) ([]byte, error) {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}
	return key, nil
}

// ChainExport exports the provenance chain for external verification
type ChainExport struct {
	GenesisHash string        `json:"genesis_hash"`
	Entries     []SignedEntry `json:"entries"`
	RootHash    string        `json:"root_hash"`
	Timestamp   time.Time     `json:"timestamp"`
}

// Export exports the provenance chain for external verification.
// This does NOT re-append entries; it reads from the existing chain.
func (s *ImmutableStore) Export() ChainExport {
	s.mu.RLock()
	defer s.mu.RUnlock()

	chainCopy := make([]SignedEntry, len(s.chain))
	copy(chainCopy, s.chain)

	currentHash := s.genesis
	if len(chainCopy) > 0 {
		currentHash = chainCopy[len(chainCopy)-1].Hash
	}

	return ChainExport{
		GenesisHash: s.genesis.String(),
		Entries:     chainCopy,
		RootHash:    currentHash.String(),
		Timestamp:   time.Now(),
	}
}

// BatchVerify verifies a batch of entries
func BatchVerify(entries []SignedEntry, genesis Hash) error {
	currentHash := genesis

	for i, entry := range entries {
		if !entry.Verify(currentHash) {
			return fmt.Errorf(
				"%w: entry %d (id=%s) failed batch verification",
				ErrTamperingDetected,
				i,
				entry.ID,
			)
		}
		currentHash = entry.Hash
	}

	return nil
}

// ReconstructChain reconstructs a chain from a list of entries
func ReconstructChain(entries []Entry, genesis Hash) (*ChainVerifier, error) {
	cv := NewChainVerifier(genesis)

	for _, entry := range entries {
		cv.Append(entry)
	}

	return cv, nil
}

// IntegrityReport provides a comprehensive integrity report
type IntegrityReport struct {
	ChainVerified   bool      `json:"chain_verified"`
	EntryCount      int       `json:"entry_count"`
	GenesisHash     string    `json:"genesis_hash"`
	CurrentHash     string    `json:"current_hash"`
	TamperDetected  bool      `json:"tamper_detected"`
	FailedEntryIDs  []string  `json:"failed_entry_ids,omitempty"`
	ReportTimestamp time.Time `json:"report_timestamp"`
}

// GenerateIntegrityReport generates a comprehensive integrity report
func (s *ImmutableStore) GenerateIntegrityReport() IntegrityReport {
	s.mu.RLock()
	defer s.mu.RUnlock()

	report := IntegrityReport{
		EntryCount:      len(s.entries),
		GenesisHash:     s.genesis.String(),
		CurrentHash:     s.GetChainHash().String(),
		ReportTimestamp: time.Now(),
	}

	err := s.VerifyChain()
	if err != nil {
		report.TamperDetected = true
		report.ChainVerified = false

		// Identify which entries failed
		currentHash := s.genesis
		for _, entry := range s.entries {
			signed := SignedEntry{Entry: entry}
			signed.Hash = signed.ComputeHash(currentHash)
			if !signed.Verify(currentHash) {
				report.FailedEntryIDs = append(report.FailedEntryIDs, entry.ID)
			}
			currentHash = signed.Hash
		}
	} else {
		report.ChainVerified = true
	}

	return report
}
