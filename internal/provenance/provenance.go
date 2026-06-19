package provenance

import (
	"github.com/ares/engine/internal/uuid"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type EntryType string

const (
	EntryDecision     EntryType = "decision"
	EntryExecution    EntryType = "execution"
	EntryVerification EntryType = "verification"
	EntryExploit      EntryType = "exploit"
	EntryReplay       EntryType = "replay"
	EntryPolicy       EntryType = "policy"
)

type Entry struct {
	ID        string            `json:"id"`
	Type      EntryType         `json:"type"`
	Agent     string            `json:"agent"`
	Action    string            `json:"action"`
	Tool      string            `json:"tool,omitempty"`
	Target    string            `json:"target,omitempty"`
	Input     string            `json:"input,omitempty"`
	Output    string            `json:"output,omitempty"`
	Decision  string            `json:"decision,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	TraceID   string            `json:"trace_id,omitempty"`
	ParentID  string            `json:"parent_id,omitempty"`
	Duration  time.Duration     `json:"duration"`
	Tags      map[string]string `json:"tags,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Signature string            `json:"signature,omitempty"`
}

type Store struct {
	mu         sync.RWMutex
	entries    []Entry
	maxSize    int
	signingKey []byte
}

func New() *Store {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		key = []byte("ares-default-signing-key-insecure")
	}
	return &Store{
		entries:    make([]Entry, 0, 1000),
		maxSize:    100000,
		signingKey: key,
	}
}

func NewWithSigningKey(key []byte) *Store {
	if len(key) < 16 {
		key = append(key, make([]byte, 16-len(key))...)
	}
	return &Store{
		entries:    make([]Entry, 0, 1000),
		maxSize:    100000,
		signingKey: key,
	}
}

func (s *Store) Record(entry Entry) {
	if entry.ID == "" {
		entry.ID = uuid.New()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	if len(s.signingKey) > 0 {
		entry.Signature = signEntry(entry, s.signingKey)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	if len(s.entries) > s.maxSize {
		s.entries = s.entries[len(s.entries)-s.maxSize:]
	}
}

func (s *Store) VerifyAll() (valid, invalid int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if len(s.signingKey) == 0 {
			invalid++
			continue
		}
		if e.Signature == "" {
			invalid++
			continue
		}
		expected := signEntry(e, s.signingKey)
		if hmac.Equal([]byte(e.Signature), []byte(expected)) {
			valid++
		} else {
			invalid++
		}
	}
	return
}

func (s *Store) VerifyEntryByID(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.ID == id {
			if len(s.signingKey) == 0 || e.Signature == "" {
				return false
			}
			expected := signEntry(e, s.signingKey)
			return hmac.Equal([]byte(e.Signature), []byte(expected))
		}
	}
	return false
}

func signEntry(entry Entry, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(entry.ID))
	mac.Write([]byte(entry.Type))
	mac.Write([]byte(entry.Agent))
	mac.Write([]byte(entry.Action))
	mac.Write([]byte(entry.Timestamp.Format(time.RFC3339Nano)))
	if entry.ParentID != "" {
		mac.Write([]byte(entry.ParentID))
	}
	if entry.TraceID != "" {
		mac.Write([]byte(entry.TraceID))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyEntry(entry Entry, key []byte) bool {
	if len(key) == 0 {
		return false
	}
	if entry.Signature == "" {
		return false
	}
	expected := signEntry(entry, key)
	return hmac.Equal([]byte(entry.Signature), []byte(expected))
}

func (s *Store) RecordDecision(agent, action, decision, reason string, tags map[string]string) {
	s.Record(Entry{
		Type:     EntryDecision,
		Agent:    agent,
		Action:   action,
		Decision: decision,
		Reason:   reason,
		Tags:     tags,
	})
}

func (s *Store) RecordExecution(agent, tool, target, input, output string, duration time.Duration) {
	s.Record(Entry{
		Type:     EntryExecution,
		Agent:    agent,
		Tool:     tool,
		Target:   target,
		Input:    input,
		Output:   output,
		Duration: duration,
	})
}

func (s *Store) RecordVerification(agent string, findingID string, result string, confidence float64) {
	s.Record(Entry{
		Type:     EntryVerification,
		Agent:    agent,
		Action:   fmt.Sprintf("verify:%s", findingID),
		Decision: result,
		Reason:   fmt.Sprintf("confidence: %.2f", confidence),
	})
}

func (s *Store) Query(agent string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Entry
	for _, e := range s.entries {
		if e.Agent == agent {
			result = append(result, e)
		}
	}
	return result
}

func (s *Store) QueryByType(entryType EntryType) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Entry
	for _, e := range s.entries {
		if e.Type == entryType {
			result = append(result, e)
		}
	}
	return result
}

func (s *Store) QueryByTrace(traceID string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Entry
	for _, e := range s.entries {
		if e.TraceID == traceID {
			result = append(result, e)
		}
	}
	return result
}

func (s *Store) QueryByTarget(target string) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Entry
	for _, e := range s.entries {
		if e.Target == target {
			result = append(result, e)
		}
	}
	return result
}

func (s *Store) All() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Entry, len(s.entries))
	copy(result, s.entries)
	return result
}

func (s *Store) Chain(traceID string) []Entry {
	entries := s.QueryByTrace(traceID)
	entryMap := make(map[string]Entry)
	for _, e := range entries {
		entryMap[e.ID] = e
	}
	var chain []Entry
	current := traceID
	for i := 0; i < 100; i++ {
		found := false
		for _, e := range entries {
			if e.ParentID == current {
				chain = append(chain, e)
				current = e.ID
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return chain
}

func (s *Store) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	byType := make(map[EntryType]int)
	byAgent := make(map[string]int)
	for _, e := range s.entries {
		byType[e.Type]++
		byAgent[e.Agent]++
	}
	return map[string]interface{}{
		"total":    len(s.entries),
		"by_type":  byType,
		"by_agent": byAgent,
	}
}

func (e Entry) String() string {
	return fmt.Sprintf("[%s] %s/%s: %s (%.0fms)", e.Timestamp.Format(time.RFC3339), e.Agent, e.Type, e.Action, e.Duration.Seconds()*1000)
}
