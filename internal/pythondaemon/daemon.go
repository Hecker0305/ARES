package pythondaemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ares/engine/internal/logger"
)

var (
	ErrDaemonNotRunning  = fmt.Errorf("python daemon not running")
	ErrDaemonTimeout     = fmt.Errorf("python daemon timeout")
	ErrCapabilityMissing = fmt.Errorf("required Python capability not available")
	ErrDaemonCircuitOpen = fmt.Errorf("python daemon circuit breaker open")
	ErrDaemonStartFailed = fmt.Errorf("python daemon start failed after retries")
)

type CircuitState int32

const (
	CircuitClosed   CircuitState = 0
	CircuitHalfOpen CircuitState = 1
	CircuitOpen     CircuitState = 2
)

const (
	DefaultMaxRetries    = 3
	DefaultBaseBackoff   = 200 * time.Millisecond
	DefaultMaxBackoff    = 10 * time.Second
	CircuitTripThreshold = 5
	CircuitHalfOpenAfter = 30 * time.Second
	HealthCheckInterval  = 5 * time.Second
	DaemonCallTimeout    = 60 * time.Second
	MaxRestartAttempts   = 5
	RestartBackoffBase   = 1 * time.Second
	RestartBackoffMax    = 30 * time.Second
)

type jsonRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      int64       `json:"id"`
}

type jsonResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *jsonRPCError   `json:"error"`
	ID      int64           `json:"id"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Capabilities struct {
	Yara     bool `json:"yara"`
	Capstone bool `json:"capstone"`
	Scapy    bool `json:"scapy"`
	Capa     bool `json:"capa"`
}

type YARAMatch struct {
	Rule    string            `json:"rule"`
	Meta    map[string]string `json:"meta"`
	Strings []YARAStringMatch `json:"strings"`
}

type YARAStringMatch struct {
	Identifier string `json:"identifier"`
	Offset     int    `json:"offset"`
	Data       string `json:"data"`
}

type DisasmSection struct {
	Section          string              `json:"section"`
	VirtualAddress   string              `json:"virtual_address"`
	Size             int64               `json:"size"`
	InstructionCount int                 `json:"instruction_count"`
	Instructions     []DisasmInstruction `json:"instructions"`
}

type DisasmInstruction struct {
	Address  string `json:"address"`
	Size     int    `json:"size"`
	Mnemonic string `json:"mnemonic"`
	OpStr    string `json:"op_str"`
}

type ScapyResult struct {
	PacketsSent int    `json:"packets_sent"`
	BytesSent   int64  `json:"bytes_sent"`
	Error       string `json:"error,omitempty"`
}

type CapaResult struct {
	Rules  []string `json:"rules,omitempty"`
	Status string   `json:"status,omitempty"`
	Reason string   `json:"reason,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type Daemon struct {
	cmd          *exec.Cmd
	stdin        *bufio.Writer
	stdout       *bufio.Scanner
	mu           sync.Mutex
	nextID       int64
	running      bool
	python       string
	ready        chan struct{}
	responses    map[int64]chan jsonResponse
	capabilities map[string]bool

	circuitState  int32
	failureCount  int32
	halfOpenTick  int32
	lastCircuitAt int64

	watchdogStop  chan struct{}
	healthTicker  *time.Ticker
	maxRetries    int
	baseBackoff   time.Duration
	maxBackoff    time.Duration
	circuitTrips  int32
	circuitResets int32

	scriptPath    string
	startAttempts int
	daemonTimeout time.Duration
}

func New() *Daemon {
	pythonPath := "python3"
	if p := os.Getenv("ARES_PYTHON"); p != "" {
		pythonPath = p
	}
	maxRetries := DefaultMaxRetries
	if v := os.Getenv("ARES_DAEMON_MAX_RETRIES"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &maxRetries); err == nil && n == 1 {
		}
	}
	return &Daemon{
		responses:     make(map[int64]chan jsonResponse),
		ready:         make(chan struct{}),
		python:        pythonPath,
		maxRetries:    maxRetries,
		baseBackoff:   DefaultBaseBackoff,
		maxBackoff:    DefaultMaxBackoff,
		daemonTimeout: DaemonCallTimeout,
	}
}

func (d *Daemon) GetCircuitState() CircuitState {
	return CircuitState(atomic.LoadInt32(&d.circuitState))
}

func (d *Daemon) GetFailureCount() int32 {
	return atomic.LoadInt32(&d.failureCount)
}

func (d *Daemon) GetCircuitTrips() int32 {
	return atomic.LoadInt32(&d.circuitTrips)
}

func (d *Daemon) GetCircuitResets() int32 {
	return atomic.LoadInt32(&d.circuitResets)
}

func (d *Daemon) HealthCheck() error {
	state := d.GetCircuitState()
	if state == CircuitOpen {
		lastTime := time.Unix(0, atomic.LoadInt64(&d.lastCircuitAt))
		if time.Since(lastTime) > CircuitHalfOpenAfter {
			if atomic.CompareAndSwapInt32(&d.circuitState, int32(CircuitOpen), int32(CircuitHalfOpen)) {
				logger.Info("[PythonDaemon] circuit breaker half-open, allowing probe")
			}
		} else {
			return ErrDaemonCircuitOpen
		}
	}

	if !d.IsRunning() {
		return ErrDaemonNotRunning
	}

	err := d.callWithRetry("ping", map[string]interface{}{}, nil)
	if err != nil {
		atomic.AddInt32(&d.failureCount, 1)
		if atomic.LoadInt32(&d.failureCount) >= CircuitTripThreshold {
			if atomic.CompareAndSwapInt32(&d.circuitState, int32(CircuitClosed), int32(CircuitOpen)) {
				atomic.StoreInt64(&d.lastCircuitAt, time.Now().UnixNano())
				atomic.AddInt32(&d.circuitTrips, 1)
				logger.Warn("[PythonDaemon] circuit breaker opened after threshold", logger.Fields{
					"failures": atomic.LoadInt32(&d.failureCount),
				})
			}
		}
		return fmt.Errorf("health check ping failed: %w", err)
	}

	if state == CircuitHalfOpen {
		if atomic.CompareAndSwapInt32(&d.circuitState, int32(CircuitHalfOpen), int32(CircuitClosed)) {
			atomic.StoreInt32(&d.failureCount, 0)
			atomic.AddInt32(&d.circuitResets, 1)
			logger.Info("[PythonDaemon] circuit breaker closed after successful probe")
		}
	}

	atomic.StoreInt32(&d.failureCount, 0)
	return nil
}

func (d *Daemon) startWithRetry() error {
	var lastErr error
	for i := 0; i < MaxRestartAttempts; i++ {
		if i > 0 {
			backoff := RestartBackoffBase * time.Duration(math.Pow(2, float64(i-1)))
			if backoff > RestartBackoffMax {
				backoff = RestartBackoffMax
			}
			jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
			time.Sleep(backoff + jitter)
		}

		err := d.tryStart()
		if err == nil {
			d.startAttempts = 0
			return nil
		}
		lastErr = err
		d.startAttempts++
		logger.Warn("[PythonDaemon] start attempt failed", logger.Fields{
			"attempt": i + 1,
			"error":   err.Error(),
		})
	}
	return fmt.Errorf("%w: %v", ErrDaemonStartFailed, lastErr)
}

func (d *Daemon) tryStart() error {
	d.mu.Lock()

	if d.running {
		d.mu.Unlock()
		return nil
	}

	scriptPath := d.findDaemonScript()
	d.scriptPath = scriptPath
	cmd := exec.Command(d.python, "-u", scriptPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		d.mu.Unlock()
		return fmt.Errorf("daemon stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		d.mu.Unlock()
		return fmt.Errorf("daemon stdout pipe: %w", err)
	}

	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		d.mu.Unlock()
		return fmt.Errorf("daemon start: %w", err)
	}

	d.cmd = cmd
	d.stdin = bufio.NewWriter(stdin)
	d.stdout = bufio.NewScanner(stdout)
	d.stdout.Split(bufio.ScanLines)
	d.running = true

	d.responses = make(map[int64]chan jsonResponse)
	d.ready = make(chan struct{})

	d.mu.Unlock()

	go d.readLoop()

	resp, err := d.callInternal(1, "ping", map[string]interface{}{})
	if err != nil {
		d.mu.Lock()
		d.stopLocked()
		d.mu.Unlock()
		return fmt.Errorf("daemon ping failed: %w", err)
	}

	var caps Capabilities
	if err := json.Unmarshal(resp, &caps); err == nil {
		d.capabilities = map[string]bool{
			"yara":     caps.Yara,
			"capstone": caps.Capstone,
			"scapy":    caps.Scapy,
			"capa":     caps.Capa,
		}
	}

	logger.Info("[PythonDaemon] started with capabilities", logger.Fields{
		"yara":     caps.Yara,
		"capstone": caps.Capstone,
		"scapy":    caps.Scapy,
		"capa":     caps.Capa,
	})

	d.startWatchdog()

	close(d.ready)
	return nil
}

func (d *Daemon) Start() error {
	return d.startWithRetry()
}

func (d *Daemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopWatchdog()
	d.stopLocked()
}

func (d *Daemon) stopLocked() {
	if d.cmd != nil && d.cmd.Process != nil {
		d.cmd.Process.Kill()
		d.cmd.Wait()
	}
	d.running = false
}

func (d *Daemon) startWatchdog() {
	d.watchdogStop = make(chan struct{})
	d.healthTicker = time.NewTicker(HealthCheckInterval)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("[PythonDaemon] watchdog panic recovered", logger.Fields{"panic": r})
			}
		}()
		for {
			select {
			case <-d.healthTicker.C:
				err := d.HealthCheck()
				if err != nil {
					logger.Warn("[PythonDaemon] health check failed, attempting restart", logger.Fields{
						"error": err.Error(),
					})
					d.mu.Lock()
					d.stopLocked()
					d.mu.Unlock()
					if startErr := d.startWithRetry(); startErr != nil {
						logger.Error("[PythonDaemon] watchdog restart failed", logger.Fields{
							"error": startErr.Error(),
						})
					}
				}
			case <-d.watchdogStop:
				d.healthTicker.Stop()
				return
			}
		}
	}()
}

func (d *Daemon) stopWatchdog() {
	if d.watchdogStop != nil {
		close(d.watchdogStop)
		d.watchdogStop = nil
	}
}

func (d *Daemon) readLoop() {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("[PythonDaemon] readLoop panic recovered", logger.Fields{"panic": r})
		}
	}()
	for d.stdout.Scan() {
		line := d.stdout.Text()
		var resp jsonResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			continue
		}
		d.mu.Lock()
		ch, ok := d.responses[resp.ID]
		if ok {
			delete(d.responses, resp.ID)
		}
		d.mu.Unlock()
		if ok {
			ch <- resp
		}
	}
	if d.IsRunning() {
		logger.Warn("[PythonDaemon] readLoop ended while daemon running — process may have exited")
	}
}

func (d *Daemon) callInternal(id int64, method string, params interface{}) (json.RawMessage, error) {
	ch := make(chan jsonResponse, 1)
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return nil, ErrDaemonNotRunning
	}
	d.responses[id] = ch
	req := jsonRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      id,
	}
	data, _ := json.Marshal(req)
	d.stdin.Write(data)
	d.stdin.Write([]byte("\n"))
	d.stdin.Flush()
	d.mu.Unlock()

	select {
	case resp := <-ch:
		if resp.Error != nil {
			return nil, fmt.Errorf("daemon error: %s", resp.Error.Message)
		}
		return resp.Result, nil
	case <-time.After(d.daemonTimeout):
		return nil, ErrDaemonTimeout
	}
}

func (d *Daemon) callWithRetry(method string, params interface{}, result interface{}) error {
	<-d.ready

	state := d.GetCircuitState()
	if state == CircuitOpen {
		lastTime := time.Unix(0, atomic.LoadInt64(&d.lastCircuitAt))
		if time.Since(lastTime) > CircuitHalfOpenAfter {
			if atomic.CompareAndSwapInt32(&d.circuitState, int32(CircuitOpen), int32(CircuitHalfOpen)) {
				logger.Info("[PythonDaemon] circuit half-open, allowing probe request")
			}
		} else {
			return ErrDaemonCircuitOpen
		}
	}

	var lastErr error
	for i := 0; i <= d.maxRetries; i++ {
		if i > 0 {
			backoff := d.baseBackoff * time.Duration(math.Pow(2, float64(i-1)))
			if backoff > d.maxBackoff {
				backoff = d.maxBackoff
			}
			jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
			time.Sleep(backoff + jitter)
		}

		d.mu.Lock()
		d.nextID++
		id := d.nextID
		d.mu.Unlock()

		raw, err := d.callInternal(id, method, params)
		if err == nil {
			if result != nil {
				if parseErr := json.Unmarshal(raw, result); parseErr != nil {
					return fmt.Errorf("daemon response parse: %w", parseErr)
				}
			}
			if state == CircuitHalfOpen {
				if atomic.CompareAndSwapInt32(&d.circuitState, int32(CircuitHalfOpen), int32(CircuitClosed)) {
					atomic.StoreInt32(&d.failureCount, 0)
					atomic.AddInt32(&d.circuitResets, 1)
					logger.Info("[PythonDaemon] circuit closed after successful retry")
				}
			}
			atomic.StoreInt32(&d.failureCount, 0)
			return nil
		}
		lastErr = err
		atomic.AddInt32(&d.failureCount, 1)

		if i < d.maxRetries {
			logger.Debug("[PythonDaemon] retrying call", logger.Fields{
				"method":  method,
				"attempt": i + 1,
				"error":   err.Error(),
			})
		}
	}

	if atomic.LoadInt32(&d.failureCount) >= CircuitTripThreshold {
		if atomic.CompareAndSwapInt32(&d.circuitState, int32(CircuitClosed), int32(CircuitOpen)) {
			atomic.StoreInt64(&d.lastCircuitAt, time.Now().UnixNano())
			atomic.AddInt32(&d.circuitTrips, 1)
			logger.Warn("[PythonDaemon] circuit opened after retries exhausted", logger.Fields{
				"failures": atomic.LoadInt32(&d.failureCount),
				"method":   method,
			})
		}
	}

	return fmt.Errorf("daemon call failed after %d retries: %w", d.maxRetries, lastErr)
}

func (d *Daemon) call(method string, params interface{}, result interface{}) error {
	return d.callWithRetry(method, params, result)
}

func (d *Daemon) YARAScan(data []byte) ([]YARAMatch, error) {
	var result struct {
		Matches []YARAMatch `json:"matches"`
	}
	err := d.call("yara", map[string]string{
		"data": string(data),
	}, &result)
	if err != nil {
		return nil, err
	}
	return result.Matches, nil
}

func (d *Daemon) Disassemble(data []byte, format string, baseAddr uint64) ([]DisasmSection, error) {
	var result struct {
		Sections []DisasmSection `json:"sections"`
	}
	err := d.call("capstone", map[string]interface{}{
		"data":      string(data),
		"format":    format,
		"base_addr": baseAddr,
	}, &result)
	if err != nil {
		return nil, err
	}
	return result.Sections, nil
}

func (d *Daemon) ScapySend(target string, port int, proto string, count int) (*ScapyResult, error) {
	var result ScapyResult
	err := d.call("scapy_send", map[string]interface{}{
		"target": target,
		"port":   port,
		"proto":  proto,
		"count":  count,
	}, &result)
	if err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, fmt.Errorf("scapy error: %s", result.Error)
	}
	return &result, nil
}

func (d *Daemon) CAPAAnalyze(filepath string) (*CapaResult, error) {
	var result CapaResult
	err := d.call("capa", map[string]string{
		"filepath": filepath,
	}, &result)
	if err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, fmt.Errorf("capa error: %s", result.Error)
	}
	return &result, nil
}

func (d *Daemon) HasCapability(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.capabilities[name]
}

func (d *Daemon) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

func (d *Daemon) findDaemonScript() string {
	locations := []string{
		filepath.Join("internal", "pythondaemon", "daemon.py"),
	}
	if wd, err := os.Getwd(); err == nil {
		locations = append(locations, filepath.Join(wd, "internal", "pythondaemon", "daemon.py"))
	}
	if root := os.Getenv("ARES_ROOT"); root != "" {
		locations = append(locations, filepath.Join(root, "internal", "pythondaemon", "daemon.py"))
	}
	execPath, _ := os.Executable()
	locations = append(locations, filepath.Join(filepath.Dir(execPath), "daemon.py"))
	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}
	return "internal/pythondaemon/daemon.py"
}
