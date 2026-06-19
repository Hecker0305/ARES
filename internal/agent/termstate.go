package agent

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/uuid"
)

var ptyEnabled = true

// SetPTYEnabled controls whether interactive PTY sessions are allowed.
// Set to false in production/hardened deployments.
func SetPTYEnabled(enabled bool) {
	ptyEnabled = enabled
}

type PTYSession struct {
	ID         string
	Cmd        string
	Args       []string
	Proc       *exec.Cmd
	Stdin      io.WriteCloser
	Stdout     io.Reader
	Stderr     io.Reader
	Pid        int
	Started    time.Time
	ExitCode   int
	Terminated bool
	mu         sync.RWMutex
	env        map[string]string
	workDir    string
}

type TerminalState struct {
	sessions    map[string]*PTYSession
	activeID    string
	mu          sync.RWMutex
	maxSessions int
}

func NewTerminalState() *TerminalState {
	return &TerminalState{
		sessions:    make(map[string]*PTYSession),
		maxSessions: 5,
	}
}

func (ts *TerminalState) NewSession(cmd string, args []string, env map[string]string, workDir string) (*PTYSession, error) {
	if !ptyEnabled {
		return nil, fmt.Errorf("PTY sessions are disabled (SetPTYEnabled(false))")
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if len(ts.sessions) >= ts.maxSessions {
		return nil, fmt.Errorf("max sessions (%d) reached", ts.maxSessions)
	}

	// Validate command against security kernel
	spec := security.CommandSpec{Binary: cmd, Args: args}
	validated := security.ValidateCommand(spec)
	if validated.Err != nil {
		return nil, fmt.Errorf("command validation rejected: %w", validated.Err)
	}

	// Generate cryptographically secure session ID
	sessionIDBytes := make([]byte, 16)
	var sessionID string
	if _, err := rand.Read(sessionIDBytes); err != nil {
		// Fallback to timestamp if crypto fails (should be extremely rare)
		sessionID = uuid.New()
	} else {
		sessionID = fmt.Sprintf("pty-%x", sessionIDBytes)
	}

	proc := exec.Command(validated.Binary, validated.Args...)
	if workDir != "" {
		proc.Dir = workDir
	}
	if env != nil {
		secureEnv := security.SecureEnvVars()
		e := make([]string, 0, len(secureEnv)+len(env))
		for k, v := range secureEnv {
			e = append(e, k+"="+v)
		}
		for k, v := range env {
			e = append(e, k+"="+v)
		}
		proc.Env = e
	}

	stdinPipe, err := proc.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutPipe, err := proc.StdoutPipe()
	if err != nil {
		stdinPipe.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := proc.StderrPipe()
	if err != nil {
		stdinPipe.Close()
		stdoutPipe.Close()
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := proc.Start(); err != nil {
		stdinPipe.Close()
		stdoutPipe.Close()
		stderrPipe.Close()
		return nil, fmt.Errorf("start process: %w", err)
	}

	session := &PTYSession{
		ID: sessionID, Cmd: validated.Binary, Args: validated.Args, Proc: proc,
		Stdin: stdinPipe, Stdout: stdoutPipe, Stderr: stderrPipe,
		Pid: getPid(proc), Started: time.Now(), env: env, workDir: workDir,
	}
	ts.sessions[sessionID] = session
	ts.activeID = sessionID
	go ts.watchExit(session)
	return session, nil
}

func termStateFromSC(sc interface{}) *TerminalState {
	ctx, ok := sc.(*ScanContext)
	if !ok || ctx == nil {
		return NewTerminalState()
	}
	if ctx.TerminalState == nil {
		ctx.TerminalState = NewTerminalState()
	}
	return ctx.TerminalState
}

func (ts *TerminalState) watchExit(s *PTYSession) {
	s.Proc.Wait()
	s.mu.Lock()
	if s.Proc.ProcessState != nil {
		s.ExitCode = s.Proc.ProcessState.ExitCode()
	}
	s.Terminated = true
	s.mu.Unlock()
}

func (ts *TerminalState) Write(sessionID, data string) (int, error) {
	if strings.ContainsAny(data, "|;&$`'\"(){}[]<>!\\\n\r") {
		return 0, fmt.Errorf("data contains shell metacharacters")
	}
	ts.mu.RLock()
	s, ok := ts.sessions[sessionID]
	ts.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("session not found: %s", sessionID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Stdin.Write([]byte(data))
}

func (ts *TerminalState) Read(sessionID string, maxBytes int) (string, error) {
	ts.mu.RLock()
	s, ok := ts.sessions[sessionID]
	ts.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("session not found: %s", sessionID)
	}
	buf := make([]byte, maxBytes)
	n, err := s.Stdout.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read stdout: %w", err)
	}
	return string(buf[:n]), nil
}

func (ts *TerminalState) ReadUntil(sessionID, until string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var output []byte
	ts.mu.RLock()
	s, ok := ts.sessions[sessionID]
	ts.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("session not found: %s", sessionID)
	}
	reader := bufio.NewReader(s.Stdout)
	for time.Now().Before(deadline) {
		b, err := reader.ReadByte()
		if err == io.EOF {
			break
		}
		output = append(output, b)
		if len(output) >= len(until) {
			tail := string(output[len(output)-len(until):])
			if tail == until {
				break
			}
		}
	}
	return string(output), nil
}

func (ts *TerminalState) GetSession(sessionID string) *PTYSession {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.sessions[sessionID]
}

func (ts *TerminalState) ListSessions() []*PTYSession {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	var out []*PTYSession
	for _, s := range ts.sessions {
		out = append(out, s)
	}
	return out
}

func (ts *TerminalState) CloseSession(sessionID string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	s, ok := ts.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found")
	}
	if s.Stdin != nil {
		s.Stdin.Close()
	}
	if s.Proc != nil && s.Proc.Process != nil && s.Proc.ProcessState != nil && !s.Proc.ProcessState.Exited() {
		s.Proc.Process.Kill()
		s.Proc.Wait()
	}
	delete(ts.sessions, sessionID)
	if ts.activeID == sessionID {
		ts.activeID = ""
	}
	return nil
}

func (ts *TerminalState) CloseAll() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for id := range ts.sessions {
		s := ts.sessions[id]
		if s.Stdin != nil {
			s.Stdin.Close()
		}
		if s.Proc != nil && s.Proc.Process != nil && s.Proc.ProcessState != nil && !s.Proc.ProcessState.Exited() {
			s.Proc.Process.Kill()
		}
	}
	ts.sessions = make(map[string]*PTYSession)
	ts.activeID = ""
}

func (ts *TerminalState) SetActive(id string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if _, ok := ts.sessions[id]; ok {
		ts.activeID = id
	}
}

func (ts *TerminalState) GetActive() string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.activeID
}

func (ts *TerminalState) SendCtrlC(sessionID string) error {
	_, err := ts.Write(sessionID, "\x03")
	return err
}

func (ts *TerminalState) SendEOF(sessionID string) error {
	ts.mu.RLock()
	s, ok := ts.sessions[sessionID]
	ts.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session not found")
	}
	return s.Stdin.Close()
}

func isWindows() bool {
	return os.PathSeparator == '\\' || runtime.GOOS == "windows"
}

func getPid(proc *exec.Cmd) int {
	if proc.Process != nil {
		return proc.Process.Pid
	}
	return -1
}

func PTTYSessionCreate(params json.RawMessage, sc interface{}) ToolResult {
	var p struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
		WorkDir string            `json:"work_dir"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err), Success: false}
	}
	if p.Command == "" {
		return ToolResult{Error: "command is required", Success: false}
	}
	if p.Args == nil {
		p.Args = []string{}
	}

	// Use platform-appropriate work directory
	if p.WorkDir == "" {
		if isWindows() {
			p.WorkDir = os.Getenv("TEMP")
			if p.WorkDir == "" {
				p.WorkDir = "C:\\Windows\\Temp"
			}
		} else {
			p.WorkDir = "/tmp"
		}
	}

	// Validate command against security kernel
	spec := security.CommandSpec{Binary: p.Command, Args: p.Args}
	validated := security.ValidateCommand(spec)
	if validated.Err != nil {
		return ToolResult{Error: fmt.Sprintf("command rejected: %v", validated.Err), Success: false}
	}

	session, err := termStateFromSC(sc).NewSession(validated.Binary, validated.Args, p.Env, p.WorkDir)
	if err != nil {
		return ToolResult{Error: err.Error(), Success: false}
	}
	return ToolResult{Content: fmt.Sprintf("session=%s pid=%d binary=%s", session.ID, session.Pid, validated.Binary), Success: true}
}

func PTTYSend(params json.RawMessage, sc interface{}) ToolResult {
	var p struct {
		SessionID string `json:"session_id"`
		Data      string `json:"data"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err), Success: false}
	}
	if p.SessionID == "" {
		p.SessionID = termStateFromSC(sc).GetActive()
	}
	if p.SessionID == "" {
		return ToolResult{Error: "no active session", Success: false}
	}
	if strings.ContainsAny(p.Data, "|;&$`'\"(){}[]<>!\\\n\r") {
		return ToolResult{Error: "data contains shell metacharacters", Success: false}
	}
	n, err := termStateFromSC(sc).Write(p.SessionID, p.Data)
	if err != nil {
		return ToolResult{Error: err.Error(), Success: false}
	}
	return ToolResult{Content: fmt.Sprintf("sent %d bytes", n), Success: true}
}

func PTTYReceive(params json.RawMessage, sc interface{}) ToolResult {
	var p struct {
		SessionID string `json:"session_id"`
		MaxBytes  int    `json:"max_bytes"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err), Success: false}
	}
	if p.SessionID == "" {
		p.SessionID = termStateFromSC(sc).GetActive()
	}
	if p.SessionID == "" {
		return ToolResult{Error: "no active session", Success: false}
	}
	if p.MaxBytes == 0 {
		p.MaxBytes = 4096
	}
	if p.MaxBytes > 65536 {
		p.MaxBytes = 65536
	}
	data, err := termStateFromSC(sc).Read(p.SessionID, p.MaxBytes)
	if err != nil {
		return ToolResult{Error: err.Error(), Success: false}
	}
	return ToolResult{Content: data, Success: true}
}

func PTTYList(params json.RawMessage, sc interface{}) ToolResult {
	sessions := termStateFromSC(sc).ListSessions()
	var lines []string
	for _, s := range sessions {
		status := "running"
		s.mu.RLock()
		if s.Terminated {
			status = fmt.Sprintf("exited=%d", s.ExitCode)
		}
		s.mu.RUnlock()
		lines = append(lines, fmt.Sprintf("%s pid=%d cmd=%s started=%s status=%s",
			s.ID, s.Pid, s.Cmd, s.Started.Format(time.RFC3339), status))
	}
	return ToolResult{Content: fmt.Sprintf("Sessions: %d\n%s", len(sessions), strings.Join(lines, "\n")), Success: true}
}

func PTTYClose(params json.RawMessage, sc interface{}) ToolResult {
	var p struct{ SessionID string }
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err), Success: false}
	}
	if p.SessionID == "" {
		return ToolResult{Error: "session_id required", Success: false}
	}
	if err := termStateFromSC(sc).CloseSession(p.SessionID); err != nil {
		return ToolResult{Error: err.Error(), Success: false}
	}
	return ToolResult{Content: "session closed: " + p.SessionID, Success: true}
}

func PTTYCtrlC(params json.RawMessage, sc interface{}) ToolResult {
	var p struct{ SessionID string }
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err), Success: false}
	}
	if p.SessionID == "" {
		p.SessionID = termStateFromSC(sc).GetActive()
	}
	if p.SessionID == "" {
		return ToolResult{Error: "no active session", Success: false}
	}
	if err := termStateFromSC(sc).SendCtrlC(p.SessionID); err != nil {
		return ToolResult{Error: err.Error(), Success: false}
	}
	return ToolResult{Content: "SIGINT sent", Success: true}
}

func PTTYAwait(params json.RawMessage, sc interface{}) ToolResult {
	var p struct {
		SessionID string `json:"session_id"`
		Until     string `json:"until"`
		Timeout   int    `json:"timeout"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err), Success: false}
	}
	if p.SessionID == "" {
		p.SessionID = termStateFromSC(sc).GetActive()
	}
	if p.SessionID == "" {
		return ToolResult{Error: "no active session", Success: false}
	}
	if p.Timeout == 0 {
		p.Timeout = 30
	}
	if p.Until == "" {
		p.Until = "$ "
	}
	data, err := termStateFromSC(sc).ReadUntil(p.SessionID, p.Until, time.Duration(p.Timeout)*time.Second)
	if err != nil {
		return ToolResult{Content: data, Error: err.Error(), Success: false}
	}
	return ToolResult{Content: data, Success: true}
}
