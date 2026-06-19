package distexec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"golang.org/x/crypto/ssh"
)

const maxTaskHistory = 10000

var shellMetaPattern = regexp.MustCompile(`[|;&$` + "`" + `'"(){}<>\!*?\\]`)

type Task struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Target   string                 `json:"target"`
	Payload  map[string]interface{} `json:"payload"`
	Priority int                    `json:"priority"`
	Status   string                 `json:"status"`
	Result   string                 `json:"result,omitempty"`
	Error    string                 `json:"error,omitempty"`
	Created  time.Time              `json:"created"`
	Started  time.Time              `json:"started,omitempty"`
	Finished time.Time              `json:"finished,omitempty"`
	Retries  int                    `json:"retries,omitempty"`
}

type Worker struct {
	ID     string `json:"id"`
	Active bool   `json:"active"`
	Queue  int    `json:"queue"`
	Host   string `json:"host,omitempty"`
}

type ExecConfig struct {
	Type        string        `json:"type"`
	Host        string        `json:"host"`
	Port        int           `json:"port"`
	User        string        `json:"user"`
	Password    string        `json:"password,omitempty"`
	KeyPath     string        `json:"key_path,omitempty"`
	KnownHosts  string        `json:"known_hosts,omitempty"`
	TaskTimeout time.Duration `json:"task_timeout"`
	MaxRetries  int           `json:"max_retries"`
}

type Executor interface {
	Execute(ctx context.Context, task *Task) (string, error)
	Close() error
}

type LocalExecutor struct{}

func NewLocalExecutor() *LocalExecutor {
	return &LocalExecutor{}
}

func (e *LocalExecutor) Close() error {
	return nil
}

func (e *LocalExecutor) Execute(ctx context.Context, task *Task) (string, error) {
	if err := validateTarget(task.Target); err != nil {
		return "", fmt.Errorf("invalid target: %w", err)
	}
	if err := validatePayload(task.Payload); err != nil {
		return "", fmt.Errorf("invalid payload: %w", err)
	}

	var cmd *exec.Cmd
	switch task.Type {
	case "verify":
		cmd = exec.CommandContext(ctx, "curl", "-sk", "-o", "/dev/null",
			"-w", "%{http_code}", "--connect-timeout", "10", "--max-time", "30",
			task.Target)
	case "recon":
		cmd = exec.CommandContext(ctx, "nmap", "-sT", "-Pn", "-T4", "--min-rate=500",
			"-p", "80,443,22,8080,8443", task.Target)
	case "exploit":
		cmd = exec.CommandContext(ctx, "echo",
			fmt.Sprintf("[distexec] exploit task %s baseline check against %s", task.ID, task.Target))
	case "scan":
		cmd = exec.CommandContext(ctx, "curl", "-sk", "-I",
			"--connect-timeout", "10", "--max-time", "30",
			task.Target)
	default:
		cmd = exec.CommandContext(ctx, "echo",
			fmt.Sprintf("distexec task %s (%s)", task.ID, task.Type))
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return stderr.String(), fmt.Errorf("exec failed: %w", err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

type SSHExecutor struct {
	config *ssh.ClientConfig
	host   string
	port   int
	client *ssh.Client
	mu     sync.Mutex
}

func NewSSHExecutor(cfg ExecConfig) (*SSHExecutor, error) {
	authMethods := []ssh.AuthMethod{}
	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}
	if cfg.KeyPath != "" {
		keyData, err := os.ReadFile(cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("read SSH key %s: %w", cfg.KeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse SSH key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}

	if cfg.KnownHosts == "" {
		return nil, fmt.Errorf("known_hosts file is required for SSH host key verification; set ExecConfig.KnownHosts")
	}
	knownHostsCB, err := knownHostsCallback(cfg.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("failed to load known_hosts: %w", err)
	}
	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: knownHostsCB,
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", addr, err)
	}

	return &SSHExecutor{
		config: sshCfg,
		host:   cfg.Host,
		port:   cfg.Port,
		client: client,
	}, nil
}

func buildRemoteCommand(args ...string) string {
	var cmd strings.Builder
	for i, arg := range args {
		if i > 0 {
			cmd.WriteByte(' ')
		}
		cmd.WriteByte('\'')
		cmd.WriteString(strings.ReplaceAll(arg, "'", "'\\''"))
		cmd.WriteByte('\'')
	}
	return cmd.String()
}

func (e *SSHExecutor) Execute(ctx context.Context, task *Task) (string, error) {
	e.mu.Lock()
	client := e.client
	e.mu.Unlock()
	if client == nil {
		return "", fmt.Errorf("SSH client not connected")
	}

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	if err := validateTarget(task.Target); err != nil {
		return "", fmt.Errorf("invalid target: %w", err)
	}
	if err := validatePayload(task.Payload); err != nil {
		return "", fmt.Errorf("invalid payload: %w", err)
	}

	var cmd string
	switch task.Type {
	case "verify":
		cmd = buildRemoteCommand("curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--connect-timeout", "10", "--max-time", "30", task.Target)
	case "scan":
		cmd = buildRemoteCommand("curl", "-sk", "-I", "--connect-timeout", "10", "--max-time", "30", task.Target)
	case "recon":
		cmd = buildRemoteCommand("nmap", "-sT", "-Pn", "-T4", "--min-rate=500", "-p", "80,443,22,8080,8443", task.Target)
	default:
		safePayload := "{}"
		if len(task.Payload) > 0 {
			sanitized := make(map[string]string)
			for k, v := range task.Payload {
				sanitized[k] = fmt.Sprintf("%v", v)
			}
			b, _ := json.Marshal(sanitized)
			safePayload = string(b)
		}
		cmd = buildRemoteCommand("echo", fmt.Sprintf("distexec ssh task %s (%s): %s", task.ID, task.Type, safePayload))
	}

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("remote exec start: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		session.Close()
		return "", ctx.Err()
	case err := <-done:
		if err != nil {
			return strings.TrimSpace(stderr.String()), fmt.Errorf("remote exec: %w", err)
		}
	}

	return strings.TrimSpace(stdout.String()), nil
}

func (e *SSHExecutor) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.client != nil {
		return e.client.Close()
	}
	return nil
}

func knownHostsCallback(path string) (ssh.HostKeyCallback, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	marker := []byte("\n")
	lines := bytes.Split(data, marker)
	hostKeys := make(map[string]ssh.PublicKey)
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		_, hosts, pk, _, _, err := ssh.ParseKnownHosts(line)
		if err != nil {
			continue
		}
		for _, h := range hosts {
			hostKeys[h] = pk
		}
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		expected, ok := hostKeys[hostname]
		if !ok {
			return fmt.Errorf("unknown host: %s", hostname)
		}
		if !bytes.Equal(key.Marshal(), expected.Marshal()) {
			return fmt.Errorf("host key mismatch for %s", hostname)
		}
		return nil
	}, nil
}

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("empty target")
	}
	if strings.ContainsAny(target, "|;&$`'\"(){}[]<>!*?\\") {
		return fmt.Errorf("target contains invalid characters")
	}
	if strings.Contains(target, "..") {
		return fmt.Errorf("path traversal detected")
	}
	if strings.Contains(target, "\x00") {
		return fmt.Errorf("null byte detected")
	}
	return nil
}

func validatePayload(payload map[string]interface{}) error {
	if payload == nil {
		return nil
	}
	for k, v := range payload {
		if shellMetaPattern.MatchString(k) {
			return fmt.Errorf("payload key %q contains shell metacharacters", k)
		}
		strVal := fmt.Sprintf("%v", v)
		if shellMetaPattern.MatchString(strVal) {
			return fmt.Errorf("payload value for key %q contains shell metacharacters", k)
		}
		if strings.Contains(strVal, "\x00") {
			return fmt.Errorf("payload value for key %q contains null byte", k)
		}
	}
	return nil
}

func sanitizeForShell(input string) string {
	result := strings.ReplaceAll(input, "'", "'\\''")
	result = strings.ReplaceAll(result, "\\", "\\\\")
	result = strings.ReplaceAll(result, "$", "\\$")
	result = strings.ReplaceAll(result, "`", "\\`")
	result = strings.ReplaceAll(result, "!", "\\!")
	return result
}

type Orchestrator struct {
	mu          sync.Mutex
	tasks       chan *Task
	results     chan *Task
	workers     map[string]*Worker
	maxWorkers  int
	taskHistory []*Task
	wg          sync.WaitGroup
	executor    Executor
	maxRetries  int
	taskTimeout time.Duration
}

func New(maxWorkers int) *Orchestrator {
	if maxWorkers <= 0 {
		maxWorkers = 5
	}
	o := &Orchestrator{
		tasks:       make(chan *Task, 1000),
		results:     make(chan *Task, 1000),
		workers:     make(map[string]*Worker),
		maxWorkers:  maxWorkers,
		taskHistory: make([]*Task, 0),
		executor:    NewLocalExecutor(),
		maxRetries:  2,
		taskTimeout: 5 * time.Minute,
	}
	for i := 0; i < maxWorkers; i++ {
		id := fmt.Sprintf("worker-%d", i+1)
		o.workers[id] = &Worker{ID: id, Active: true, Queue: 0}
	}
	return o
}

func (o *Orchestrator) SetExecutor(exec Executor) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.executor != nil {
		o.executor.Close()
	}
	o.executor = exec
}

func (o *Orchestrator) SetMaxRetries(n int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.maxRetries = n
}

func (o *Orchestrator) SetTaskTimeout(d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.taskTimeout = d
}

func (o *Orchestrator) Submit(task *Task) error {
	task.Created = time.Now()
	task.Status = "queued"
	select {
	case o.tasks <- task:
		o.mu.Lock()
		o.taskHistory = append(o.taskHistory, task)
		if len(o.taskHistory) > maxTaskHistory {
			o.taskHistory = o.taskHistory[len(o.taskHistory)-maxTaskHistory:]
		}
		o.mu.Unlock()
		return nil
	default:
		return fmt.Errorf("task queue full (cap: 1000)")
	}
}

func (o *Orchestrator) SubmitBatch(tasks []*Task) []error {
	errs := make([]error, 0, len(tasks))
	for _, t := range tasks {
		if err := o.Submit(t); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (o *Orchestrator) Start(ctx context.Context) {
	o.mu.Lock()
	exec := o.executor
	maxRetries := o.maxRetries
	taskTimeout := o.taskTimeout
	o.mu.Unlock()

	for i := 0; i < o.maxWorkers; i++ {
		o.wg.Add(1)
		go o.workerLoop(ctx, fmt.Sprintf("worker-%d", i+1), exec, maxRetries, taskTimeout)
	}
	go func() {
		<-ctx.Done()
		o.mu.Lock()
		if o.executor != nil {
			o.executor.Close()
		}
		o.mu.Unlock()
		close(o.tasks)
		o.wg.Wait()
		close(o.results)
	}()
}

func backoffDuration(attempt int) time.Duration {
	base := time.Second
	maxJitter := time.Second
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxJitter)))
	if err != nil {
		jitter := time.Second
		return base*time.Duration(1<<uint(attempt)) + jitter
	}
	jitter := time.Duration(n.Int64())
	return base*time.Duration(1<<uint(attempt)) + jitter
}

func (o *Orchestrator) workerLoop(ctx context.Context, workerID string, exec Executor, maxRetries int, taskTimeout time.Duration) {
	defer o.wg.Done()
	logger.Info(fmt.Sprintf("[DistExec] Worker %s started", workerID))
	for {
		select {
		case <-ctx.Done():
			logger.Info(fmt.Sprintf("[DistExec] Worker %s stopping (ctx done)", workerID))
			return
		case task, ok := <-o.tasks:
			if !ok {
				return
			}

			o.mu.Lock()
			if w, ok := o.workers[workerID]; ok {
				w.Queue++
				w.Active = true
			}
			o.mu.Unlock()

			task.Status = "running"
			task.Started = time.Now()

			execCtx, execCancel := context.WithTimeout(ctx, taskTimeout)
			result, execErr := exec.Execute(execCtx, task)
			execCancel()

			if execErr != nil {
				if ctx.Err() != nil {
					task.Status = "cancelled"
					o.mu.Lock()
					if w, ok := o.workers[workerID]; ok {
						w.Queue--
						w.Active = false
					}
					o.mu.Unlock()
					return
				}

				if task.Retries < maxRetries {
					task.Retries++
					backoff := backoffDuration(task.Retries)
					logger.Info(fmt.Sprintf("[DistExec] Task %s failed (attempt %d/%d), retrying in %v: %v",
						task.ID, task.Retries, maxRetries, backoff, execErr))
					time.Sleep(backoff)

					task.Status = "retrying"
					task.Started = time.Now()
					retryCtx, retryCancel := context.WithTimeout(ctx, taskTimeout)
					result, execErr = exec.Execute(retryCtx, task)
					retryCancel()
				}
			}

			task.Finished = time.Now()

			if execErr != nil {
				task.Status = "failed"
				task.Error = execErr.Error()
				logger.Error(fmt.Sprintf("[DistExec] Task %s failed after %d retries: %v",
					task.ID, task.Retries, execErr))
			} else {
				task.Status = "completed"
				task.Result = result
			}

			o.mu.Lock()
			if w, ok := o.workers[workerID]; ok {
				w.Queue--
				w.Active = false
			}
			o.mu.Unlock()

			select {
			case o.results <- task:
			default:
				logger.Warn(fmt.Sprintf("[DistExec] Result channel full, dropping task %s", task.ID))
			}
		}
	}
}

func (o *Orchestrator) Results() <-chan *Task {
	return o.results
}

func (o *Orchestrator) Status() map[string]interface{} {
	o.mu.Lock()
	defer o.mu.Unlock()

	queueSize := len(o.tasks)
	activeWorkers := 0
	totalQueued := 0
	for _, w := range o.workers {
		if w.Active {
			activeWorkers++
		}
		totalQueued += w.Queue
	}

	totalTasks := len(o.taskHistory)
	failedTasks := 0
	completedTasks := 0
	retryTasks := 0
	for _, t := range o.taskHistory {
		switch t.Status {
		case "failed":
			failedTasks++
		case "completed":
			completedTasks++
		case "retrying":
			retryTasks++
		}
	}

	return map[string]interface{}{
		"queue_size":      queueSize,
		"active_workers":  activeWorkers,
		"total_workers":   len(o.workers),
		"total_queued":    totalQueued,
		"total_tasks":     totalTasks,
		"completed_tasks": completedTasks,
		"failed_tasks":    failedTasks,
		"retry_tasks":     retryTasks,
	}
}

func (o *Orchestrator) QueueSize() int {
	return len(o.tasks)
}

func (o *Orchestrator) Workers() map[string]*Worker {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := make(map[string]*Worker, len(o.workers))
	for k, v := range o.workers {
		cp := *v
		result[k] = &cp
	}
	return result
}

func (o *Orchestrator) TaskHistory() []*Task {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := make([]*Task, len(o.taskHistory))
	for i, t := range o.taskHistory {
		cp := *t
		result[i] = &cp
	}
	return result
}
