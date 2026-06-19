package airgap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

type AirGapConfig struct {
	Enabled            bool     `json:"enabled"`
	AllowedDomains     []string `json:"allowed_domains"`
	AllowListIPs       []string `json:"allow_list_ips"`
	BlockListIPs       []string `json:"block_list_ips"`
	NoExternalLLM      bool     `json:"no_external_llm"`
	LocalModelsOnly    bool     `json:"local_models_only"`
	DisableTelemetry   bool     `json:"disable_telemetry"`
	DisableUpdateCheck bool     `json:"disable_update_check"`
	AllowedTools       []string `json:"allowed_tools"`
}

type toolHash struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type AirGapManager struct {
	mu         sync.RWMutex
	config     AirGapConfig
	toolHashes []toolHash
}

func NewAirGapManager(config AirGapConfig) *AirGapManager {
	m := &AirGapManager{
		config:     config,
		toolHashes: defaultToolHashes(),
	}
	if manifestPath := os.Getenv("ARES_AIRGAP_MANIFEST"); manifestPath != "" {
		if hashes, err := loadManifest(manifestPath); err == nil {
			m.toolHashes = hashes
		}
	}
	return m
}

func (m *AirGapManager) IsAirGapped() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.config.Enabled {
		return false
	}
	return detectAirGap()
}

func detectAirGap() bool {
	if !hasPhysicalInterface() {
		return true
	}
	if !hasDefaultRoute() {
		return true
	}
	if !hasARPEntries() {
		return true
	}
	return false
}

func hasPhysicalInterface() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil || ipnet.IP.To16() != nil {
					return true
				}
			}
		}
	}
	return false
}

func hasDefaultRoute() bool {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
		if err != nil {
			return false
		}
		return len(strings.TrimSpace(string(out))) > 0
	case "darwin":
		out, err := exec.Command("netstat", "-rn", "-f", "inet").CombinedOutput()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), "default")
	case "windows":
		out, err := exec.Command("route", "print", "0.0.0.0").CombinedOutput()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), "0.0.0.0")
	default:
		return true
	}
}

func hasARPEntries() bool {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "neigh", "show").CombinedOutput()
		if err != nil {
			return false
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			if strings.Contains(line, "REACHABLE") || strings.Contains(line, "STALE") || strings.Contains(line, "DELAY") {
				return true
			}
		}
		return false
	case "darwin":
		out, err := exec.Command("arp", "-a").CombinedOutput()
		if err != nil {
			return false
		}
		return len(strings.TrimSpace(string(out))) > 0
	case "windows":
		out, err := exec.Command("arp", "-a").CombinedOutput()
		if err != nil {
			return false
		}
		return len(strings.TrimSpace(string(out))) > 0
	default:
		return true
	}
}

func (m *AirGapManager) ValidateExternalRequest(rawURL string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.config.Enabled {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	for _, ip := range m.config.BlockListIPs {
		if host == ip {
			return false
		}
	}
	if len(m.config.AllowedDomains) > 0 {
		for _, domain := range m.config.AllowedDomains {
			if host == domain || strings.HasSuffix(host, "."+domain) {
				for _, ip := range m.config.BlockListIPs {
					if host == ip {
						return false
					}
				}
				return true
			}
		}
		return false
	}
	return true
}

func (m *AirGapManager) ValidateTool(toolName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.config.Enabled || len(m.config.AllowedTools) == 0 {
		return true
	}
	for _, t := range m.config.AllowedTools {
		if t == toolName {
			return true
		}
	}
	return false
}

func (m *AirGapManager) VerifyToolHashOnExec(toolName string, toolPath string) error {
	m.mu.RLock()
	enabled := m.config.Enabled
	hashes := make([]toolHash, len(m.toolHashes))
	copy(hashes, m.toolHashes)
	m.mu.RUnlock()

	if !enabled {
		return nil
	}

	for _, th := range hashes {
		if th.Name == toolName {
			if !VerifyToolHash(toolPath, th.SHA256) {
				return fmt.Errorf("tool hash mismatch for %s: expected %s", toolName, th.SHA256)
			}
			return nil
		}
	}

	return fmt.Errorf("tool %s not found in allowed manifest", toolName)
}

func (m *AirGapManager) RefreshToolHashes() error {
	manifestPath := os.Getenv("ARES_AIRGAP_MANIFEST")
	if manifestPath == "" {
		return fmt.Errorf("no manifest path configured")
	}

	hashes, err := loadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to load manifest: %w", err)
	}

	m.mu.Lock()
	m.toolHashes = hashes
	m.mu.Unlock()

	return nil
}

func (m *AirGapManager) GetAllowedDomains() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.config.AllowedDomains))
	copy(out, m.config.AllowedDomains)
	return out
}

func (m *AirGapManager) GetBlockedIPs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.config.BlockListIPs))
	copy(out, m.config.BlockListIPs)
	return out
}

func (m *AirGapManager) GetConfig() AirGapConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

func (m *AirGapManager) SetConfig(cfg AirGapConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
}

func defaultToolHashes() []toolHash {
	return []toolHash{
		{Name: "nmap", SHA256: "e1b0c3d9a5f2e4b8c7a6d9f0e3b2c5a8d7f6e9b0c3a2d5f8e7b4c1a0d9f6e3"},
		{Name: "ffuf", SHA256: "a2b1c4d7e8f9a0b3c2d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6"},
		{Name: "gobuster", SHA256: "b3c2d5e8f9a0b1c4d7e8f9a0b3c2d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"},
		{Name: "curl", SHA256: "c4d3e6f9a0b1c2d5e8f9a0b3c4d7e8f9a0b1c2d5e6f7a8b9c0d1e2f3a4b5c6"},
		{Name: "wget", SHA256: "d5e4f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5"},
		{Name: "dig", SHA256: "e6f5a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6"},
		{Name: "nslookup", SHA256: "f7a6b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"},
		{Name: "openssl", SHA256: "a8b7c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7"},
		{Name: "python3", SHA256: "b9c8d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8"},
		{Name: "ping", SHA256: "c0d9e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9"},
	}
}

func loadManifest(path string) ([]toolHash, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Tools []toolHash `json:"tools"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	return manifest.Tools, nil
}

func VerifyToolHash(toolPath, expectedHash string) bool {
	data, err := os.ReadFile(toolPath)
	if err != nil {
		return false
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]) == expectedHash
}

func GenerateManifest(toolPaths map[string]string) ([]byte, error) {
	var tools []toolHash
	for name, path := range toolPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", path, err)
		}
		h := sha256.Sum256(data)
		tools = append(tools, toolHash{
			Name:   name,
			SHA256: hex.EncodeToString(h[:]),
		})
	}
	manifest := struct {
		Tools       []toolHash `json:"tools"`
		GeneratedAt string     `json:"generated_at"`
	}{
		Tools:       tools,
		GeneratedAt: os.Getenv("ARES_VERSION"),
	}
	return json.MarshalIndent(manifest, "", "  ")
}
