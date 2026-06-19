package mythic

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type MythicConfig struct {
	ServerURL   string `json:"server_url"`
	APIKey      string `json:"api_key,omitempty"`
	APIToken    string `json:"api_token,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	WSSEndpoint string `json:"wss_endpoint,omitempty"`
}

type MythicCallback struct {
	ID              int       `json:"id"`
	AgentCallbackID string    `json:"agent_callback_id"`
	User            string    `json:"user"`
	Computer        string    `json:"computer"`
	Domain          string    `json:"domain"`
	InternalIP      string    `json:"internal_ip"`
	ExternalIP      string    `json:"external_ip"`
	ProcessName     string    `json:"process_name"`
	PID             int       `json:"pid"`
	Architecture    string    `json:"architecture"`
	PayloadType     string    `json:"payload_type"`
	LastCheckin     time.Time `json:"last_checkin"`
	Active          bool      `json:"active"`
}

type MythicTask struct {
	ID         int                    `json:"id"`
	CallbackID int                    `json:"callback_id"`
	Command    string                 `json:"command"`
	Params     map[string]interface{} `json:"params,omitempty"`
	Status     string                 `json:"status"`
	Result     string                 `json:"result,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

type MythicPayload struct {
	ID                int      `json:"id"`
	PayloadType       string   `json:"payload_type"`
	Tag               string   `json:"tag"`
	Description       string   `json:"description"`
	OperatingSystem   string   `json:"operating_system"`
	FileSize          int      `json:"file_size"`
	SupportedCommands []string `json:"supported_commands"`
}

type MythicEngine struct {
	mu          sync.RWMutex
	config      MythicConfig
	httpClient  *http.Client
	connected   bool
	apiToken    string
	callbacks   map[int]*MythicCallback
	tasks       map[int]*MythicTask
	payloads    map[int]*MythicPayload
	wsConnected bool
}

func NewMythicEngine(config MythicConfig) *MythicEngine {
	return &MythicEngine{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		callbacks:  make(map[int]*MythicCallback),
		tasks:      make(map[int]*MythicTask),
		payloads:   make(map[int]*MythicPayload),
	}
}

func (e *MythicEngine) Login(username, password string) error {
	payload := map[string]string{
		"username": username,
		"password": password,
	}
	body, _ := json.Marshal(payload)

	resp, err := e.httpClient.Post(
		e.config.ServerURL+"/api/v1.4/user/login",
		"application/json",
		strings.NewReader(string(body)),
	)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read login response: %w", err)
	}

	var result struct {
		Status   string `json:"status"`
		APIToken string `json:"api_token"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parse login response: %w", err)
	}
	if result.Status != "success" {
		return fmt.Errorf("login failed: %s", string(data))
	}

	e.mu.Lock()
	e.apiToken = result.APIToken
	e.connected = true
	e.mu.Unlock()

	return nil
}

func (e *MythicEngine) LoginWithAPIKey(apiKey string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.testAPIConnection(apiKey); err != nil {
		return fmt.Errorf("api key auth: %w", err)
	}

	e.apiToken = apiKey
	e.connected = true
	return nil
}

func (e *MythicEngine) IsConnected() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.connected
}

func (e *MythicEngine) Logout() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.connected {
		return nil
	}

	e.apiToken = ""
	e.connected = false
	return nil
}

func (e *MythicEngine) testAPIConnection(token string) error {
	req, err := http.NewRequest("GET", e.config.ServerURL+"/api/v1.4/ping", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("api ping returned status %d", resp.StatusCode)
	}
	return nil
}

func (e *MythicEngine) apiCall(method, endpoint string, body io.Reader) ([]byte, error) {
	e.mu.RLock()
	token := e.apiToken
	e.mu.RUnlock()

	url := e.config.ServerURL + endpoint
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api call: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api error %d: %s", resp.StatusCode, string(data))
	}

	return data, nil
}
