package replay

import (
	"github.com/ares/engine/internal/uuid"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ActionType string

const (
	ActionCommand ActionType = "command"
	ActionHTTP    ActionType = "http_request"
	ActionExploit ActionType = "exploit"
	ActionResult  ActionType = "result"
)

type RecordedAction struct {
	ID        string            `json:"id"`
	Type      ActionType        `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Command   string            `json:"command,omitempty"`
	Request   *HTTPRequest      `json:"request,omitempty"`
	Response  *HTTPResponse     `json:"response,omitempty"`
	Hash      string            `json:"hash"`
	Duration  time.Duration     `json:"duration"`
	Tags      map[string]string `json:"tags,omitempty"`
}

type HTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type HTTPResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type Session struct {
	ID        string           `json:"id"`
	Target    string           `json:"target"`
	Actions   []RecordedAction `json:"actions"`
	StartTime time.Time        `json:"start_time"`
	EndTime   time.Time        `json:"end_time"`
	Summary   string           `json:"summary"`
	Hash      string           `json:"hash"`
}

type Recorder struct {
	mu            sync.Mutex
	activeSession *Session
	sessions      []*Session
	replayDir     string
	encKey        [32]byte
}

func New(replayDir string) *Recorder {
	if replayDir == "" {
		replayDir = filepath.Join(os.TempDir(), "ares_replays")
	}
	os.MkdirAll(replayDir, 0700)
	key := sha256.Sum256([]byte(replayDir + time.Now().String()))
	return &Recorder{
		replayDir: replayDir,
		sessions:  make([]*Session, 0),
		encKey:    key,
	}
}

func (r *Recorder) StartSession(target string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()

	session := &Session{
		ID:        uuid.New(),
		Target:    target,
		Actions:   make([]RecordedAction, 0),
		StartTime: time.Now(),
	}
	r.activeSession = session
	return session
}

func (r *Recorder) Record(action RecordedAction) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.activeSession == nil {
		return fmt.Errorf("no active recording session")
	}

	if action.ID == "" {
		action.ID = fmt.Sprintf("act-%d", len(r.activeSession.Actions))
	}
	if action.Timestamp.IsZero() {
		action.Timestamp = time.Now()
	}

	data := fmt.Sprintf("%s|%s|%s|%d", action.ID, action.Type, action.Command, action.Timestamp.UnixNano())
	hash := sha256.Sum256([]byte(data))
	action.Hash = fmt.Sprintf("%x", hash[:8])

	r.activeSession.Actions = append(r.activeSession.Actions, action)
	return nil
}

func (r *Recorder) RecordCommand(command string, duration time.Duration, tags map[string]string) error {
	return r.Record(RecordedAction{
		Type:     ActionCommand,
		Command:  command,
		Duration: duration,
		Tags:     tags,
	})
}

func (r *Recorder) RecordHTTP(method, url string, reqHeaders map[string]string, reqBody string, resp *HTTPResponse, duration time.Duration, tags map[string]string) error {
	return r.Record(RecordedAction{
		Type: ActionHTTP,
		Request: &HTTPRequest{
			Method:  method,
			URL:     url,
			Headers: reqHeaders,
			Body:    reqBody,
		},
		Response: resp,
		Duration: duration,
		Tags:     tags,
	})
}

func (r *Recorder) EndSession() (*Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.activeSession == nil {
		return nil, fmt.Errorf("no active session")
	}

	r.activeSession.EndTime = time.Now()
	r.activeSession.Summary = r.buildSummary(r.activeSession)

	data, err := json.Marshal(r.activeSession)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session: %v", err)
	}

	encrypted, err := r.encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt replay: %w", err)
	}

	filePath := filepath.Join(r.replayDir, r.activeSession.ID+".json")
	if err := os.WriteFile(filePath, encrypted, 0600); err != nil {
		return nil, fmt.Errorf("failed to save replay: %w", err)
	}

	session := r.activeSession
	r.sessions = append(r.sessions, session)
	r.activeSession = nil

	return session, nil
}

func (r *Recorder) buildSummary(session *Session) string {
	var parts []string
	for _, action := range session.Actions {
		switch action.Type {
		case ActionCommand:
			parts = append(parts, fmt.Sprintf("CMD: %s", truncate(action.Command, 60)))
		case ActionHTTP:
			if action.Request != nil {
				parts = append(parts, fmt.Sprintf("HTTP %s %s", action.Request.Method, action.Request.URL))
			}
		case ActionExploit:
			parts = append(parts, fmt.Sprintf("EXPLOIT: %s", truncate(action.Command, 60)))
		}
	}
	return strings.Join(parts, " → ")
}

type ActionExecutor func(action RecordedAction) (string, error)

func (r *Recorder) Replay(sessionID string) (*Session, error) {
	if !validSessionID.MatchString(sessionID) {
		return nil, fmt.Errorf("invalid session ID: %q", sessionID)
	}
	filePath := filepath.Join(r.replayDir, sessionID+".json")
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	absReplayDir, err := filepath.Abs(r.replayDir)
	if err != nil {
		return nil, fmt.Errorf("invalid replay dir: %w", err)
	}
	if !strings.HasPrefix(absPath, absReplayDir+string(filepath.Separator)) {
		return nil, fmt.Errorf("path traversal detected: %s", sessionID)
	}
	encrypted, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("replay session %s not found: %w", sessionID, err)
	}

	data, err := r.decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt replay session %s: %w", sessionID, err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to parse replay: %w", err)
	}

	return &session, nil
}

func (r *Recorder) ReplayAndExecute(sessionID string, executor ActionExecutor) (*Session, error) {
	session, err := r.Replay(sessionID)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.activeSession = &Session{
		ID:        uuid.New(),
		Target:    session.Target,
		Actions:   make([]RecordedAction, 0),
		StartTime: time.Now(),
	}
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		if r.activeSession != nil && r.activeSession.ID != "" && strings.HasPrefix(r.activeSession.ID, "replay-exec-") {
			r.activeSession = nil
		}
		r.mu.Unlock()
	}()

	for i, action := range session.Actions {
		result, execErr := executor(action)
		if execErr != nil {
			if recErr := r.Record(RecordedAction{
				Type:    ActionResult,
				Command: fmt.Sprintf("replay action %d failed: %v", i, execErr),
				Tags:    map[string]string{"replayed": sessionID, "status": "failed"},
			}); recErr != nil {
				return nil, fmt.Errorf("failed to record failure action %d: %w", i, recErr)
			}
			continue
		}
		if recErr := r.Record(RecordedAction{
			Type:    ActionResult,
			Command: fmt.Sprintf("replay action %d", i),
			Tags:    map[string]string{"replayed": sessionID, "status": "success", "result": truncate(result, 200)},
		}); recErr != nil {
			return nil, fmt.Errorf("failed to record success action %d: %w", i, recErr)
		}
	}

	return r.EndSession()
}

func (r *Recorder) ReplayAll(target string) []*Session {
	r.mu.Lock()
	defer r.mu.Unlock()

	var matches []*Session
	for _, s := range r.sessions {
		if s.Target == target {
			matches = append(matches, s)
		}
	}
	return matches
}

func (r *Recorder) Compare(session1ID, session2ID string) ([]string, error) {
	s1, err := r.Replay(session1ID)
	if err != nil {
		return nil, err
	}
	s2, err := r.Replay(session2ID)
	if err != nil {
		return nil, err
	}

	var diffs []string
	maxLen := len(s1.Actions)
	if len(s2.Actions) > maxLen {
		maxLen = len(s2.Actions)
	}

	for i := 0; i < maxLen; i++ {
		if i >= len(s1.Actions) {
			diffs = append(diffs, fmt.Sprintf("Action %d: only in session 2 (%s)", i, s2.Actions[i].Command))
			continue
		}
		if i >= len(s2.Actions) {
			diffs = append(diffs, fmt.Sprintf("Action %d: only in session 1 (%s)", i, s1.Actions[i].Command))
			continue
		}
		if s1.Actions[i].Hash != s2.Actions[i].Hash {
			diffs = append(diffs, fmt.Sprintf("Action %d differs: %q vs %q",
				i, truncate(s1.Actions[i].Command, 40), truncate(s2.Actions[i].Command, 40)))
		}
	}

	return diffs, nil
}

func (r *Recorder) Sessions() []*Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]*Session, len(r.sessions))
	copy(result, r.sessions)
	return result
}

func (r *Recorder) Active() *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activeSession != nil {
		cp := *r.activeSession
		return &cp
	}
	return nil
}

func (r *Recorder) ExportJSON(sessionID string) ([]byte, error) {
	session, err := r.Replay(sessionID)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(session, "", "  ")
}

func (r *Recorder) Stats() map[string]interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	totalActions := 0
	for _, s := range r.sessions {
		totalActions += len(s.Actions)
	}
	return map[string]interface{}{
		"sessions":      len(r.sessions),
		"total_actions": totalActions,
	}
}

func (r *Recorder) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(r.encKey[:])
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

func (r *Recorder) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(r.encKey[:])
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

var validSessionID = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "://", "_")
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "..."
}
