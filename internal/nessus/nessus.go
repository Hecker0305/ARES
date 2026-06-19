package nessus

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type NessusConfig struct {
	Host       string
	Port       int
	AccessKey  string
	SecretKey  string
	Username   string
	Password   string
	SSLVerify  bool
	APIVersion string
}

type NessusScan struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	PolicyID  int       `json:"policy_id"`
	FolderID  int       `json:"folder_id"`
	Target    string    `json:"target"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
}

type NessusPolicy struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	TemplateType string `json:"template_type"`
	Owner        string `json:"owner"`
	Visibility   string `json:"visibility"`
}

type NessusVulnerability struct {
	PluginID     int     `json:"plugin_id"`
	PluginName   string  `json:"plugin_name"`
	Severity     string  `json:"severity"`
	CVSS3Score   float64 `json:"cvss3_score,omitempty"`
	CVSS2Score   float64 `json:"cvss2_score,omitempty"`
	Host         string  `json:"host"`
	Port         int     `json:"port"`
	Protocol     string  `json:"protocol"`
	Synopsis     string  `json:"synopsis"`
	Description  string  `json:"description"`
	Solution     string  `json:"solution"`
	Output       string  `json:"output"`
	PluginFamily string  `json:"plugin_family"`
	PluginType   string  `json:"plugin_type"`
}

type NessusFolder struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type NessusEngine struct {
	config    NessusConfig
	client    *http.Client
	token     string
	apiToken  string
	secretKey string
	sessionID string
	mu        sync.RWMutex
}

func NewNessusEngine(config NessusConfig) *NessusEngine {
	tr := &http.Transport{}
	if !config.SSLVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if config.Port == 0 {
		config.Port = 8834
	}
	if config.APIVersion == "" {
		config.APIVersion = "v10"
	}
	return &NessusEngine{
		config: config,
		client: &http.Client{
			Transport: tr,
			Timeout:   time.Second * 60,
		},
	}
}

func (e *NessusEngine) Login(username, password string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	url := fmt.Sprintf("https://%s:%d/session", e.config.Host, e.config.Port)
	body := fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login returned status %d", resp.StatusCode)
	}

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("failed to parse login response: %w", err)
	}

	e.token = result.Token
	e.sessionID = result.Token
	e.apiToken = ""
	e.config.Username = username
	e.config.Password = password
	return nil
}

func (e *NessusEngine) LoginWithAPIKey(accessKey, secretKey string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.apiToken = accessKey
	e.secretKey = secretKey
	e.token = ""
	e.sessionID = ""
	e.config.Username = ""
	e.config.Password = ""
	e.config.AccessKey = accessKey
	e.config.SecretKey = secretKey
	return nil
}

func (e *NessusEngine) Logout() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.token != "" {
		url := fmt.Sprintf("https://%s:%d/session", e.config.Host, e.config.Port)
		req, err := http.NewRequest("DELETE", url, nil)
		if err != nil {
			return fmt.Errorf("logout request failed: %w", err)
		}
		req.Header.Set("X-Cookie", fmt.Sprintf("token=%s", e.token))
		e.client.Do(req)
	}

	e.token = ""
	e.sessionID = ""
	e.apiToken = ""
	e.secretKey = ""
	return nil
}

func (e *NessusEngine) IsAuthenticated() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.token != "" || e.apiToken != "" || e.sessionID != ""
}

func (e *NessusEngine) baseURL() string {
	return fmt.Sprintf("https://%s:%d", e.config.Host, e.config.Port)
}

func (e *NessusEngine) apiURL(path string) string {
	apiPath := path
	if !strings.HasPrefix(path, "/") {
		apiPath = "/" + path
	}
	return fmt.Sprintf("%s/%s%s", e.baseURL(), e.config.APIVersion, apiPath)
}

func (e *NessusEngine) request(method, urlStr, body string) (*http.Response, error) {
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, urlStr, strings.NewReader(body))
	} else {
		req, err = http.NewRequest(method, urlStr, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	e.mu.RLock()
	if e.token != "" {
		req.Header.Set("X-Cookie", fmt.Sprintf("token=%s", e.token))
	}
	if e.apiToken != "" {
		req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", e.apiToken, e.secretKey))
	}
	e.mu.RUnlock()

	return e.client.Do(req)
}
