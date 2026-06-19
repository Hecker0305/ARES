package intelligence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// K1 — Dark Web Monitoring
type DarkWebMonitor struct {
	torProxy string
}

func NewDarkWebMonitor() *DarkWebMonitor {
	return &DarkWebMonitor{
		torProxy: "socks5://127.0.0.1:9050",
	}
}

func (d *DarkWebMonitor) CheckOnionSite(onionURL string) (string, error) {
	cmd := exec.Command("torsocks", "curl", "-s", "--max-time", "30", onionURL)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("tor request: %w", err)
	}
	return stdout.String(), nil
}

func (d *DarkWebMonitor) MonitorRansomwareSites() map[string]string {
	sites := map[string]string{
		"LockBit": "http://lockbit7z2jwcbeqixag57l57qj6qbo7o3cdr6e5o6xdfk3jluyd.b32.onion/",
		"ALPHV":   "http://alphv5j7lwj6l4z5.onion/",
		"Clop":    "http://clopv3r2zh5v7a4e.onion/",
	}
	results := make(map[string]string)
	for name, url := range sites {
		content, err := d.CheckOnionSite(url)
		if err != nil {
			results[name] = fmt.Sprintf("unreachable: %v", err)
		} else {
			results[name] = fmt.Sprintf("accessible (%d bytes)", len(content))
		}
	}
	return results
}

// K2 — Threat Actor Attribution
type AttributionEngine struct{}

func NewAttributionEngine() *AttributionEngine {
	return &AttributionEngine{}
}

func (a *AttributionEngine) FingerprintTTP(ttps []string) []string {
	actorMap := map[string][]string{
		"APT29":   {"T1003", "T1059", "T1071", "T1566"},
		"APT28":   {"T1204", "T1566", "T1071"},
		"Lazarus": {"T1204", "T1059", "T1027"},
		"FIN7":    {"T1566", "T1204", "T1059"},
	}
	var matches []string
	for actor, actorTTPs := range actorMap {
		for _, ttp := range ttps {
			for _, at := range actorTTPs {
				if ttp == at {
					matches = append(matches, actor)
					break
				}
			}
		}
	}
	return matches
}

// K3 — Honeytoken Behavioral Profiling
type HoneytokenProfiler struct{}

func NewHoneytokenProfiler() *HoneytokenProfiler {
	return &HoneytokenProfiler{}
}

func (h *HoneytokenProfiler) AnalyzeTrigger(sourceIP, userAgent string) map[string]interface{} {
	result := make(map[string]interface{})
	result["source_ip"] = sourceIP
	result["user_agent"] = userAgent
	result["timestamp"] = time.Now().UTC()

	uaLower := strings.ToLower(userAgent)
	switch {
	case strings.Contains(uaLower, "curl"):
		result["tool"] = "curl"
	case strings.Contains(uaLower, "wget"):
		result["tool"] = "wget"
	case strings.Contains(uaLower, "python"):
		result["tool"] = "python"
	case strings.Contains(uaLower, "go-http"):
		result["tool"] = "go"
	default:
		result["tool"] = "browser/unknown"
	}
	return result
}

// K4 — Supply Chain Attack Detection
type SupplyChainDetector struct{}

func NewSupplyChainDetector() *SupplyChainDetector {
	return &SupplyChainDetector{}
}

func (s *SupplyChainDetector) CheckDependencyConfusion(packageName, registryURL string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/%s", registryURL, packageName))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (s *SupplyChainDetector) CheckTyposquatting(legitimateName string) []string {
	variations := []string{
		strings.ReplaceAll(legitimateName, "o", "0"),
		strings.ReplaceAll(legitimateName, "l", "1"),
		strings.ReplaceAll(legitimateName, "e", "3"),
		legitimateName + "-official",
		legitimateName + "-lib",
		legitimateName + "-core",
	}
	var found []string
	for _, v := range variations {
		if v != legitimateName {
			found = append(found, v)
		}
	}
	return found
}

// K5 — SBOM-Based Vulnerability Scanning
type SBOMScanner struct{}

func NewSBOMScanner() *SBOMScanner {
	return &SBOMScanner{}
}

func (s *SBOMScanner) ParseSBOM(sbomPath string) (map[string]string, error) {
	data, err := exec.Command("syft", "packages", "file://"+sbomPath, "-o", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("syft: %w", err)
	}
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	components := make(map[string]string)
	if artifacts, ok := result["artifacts"].([]interface{}); ok {
		for _, a := range artifacts {
			if art, ok := a.(map[string]interface{}); ok {
				name, _ := art["name"].(string)
				version, _ := art["version"].(string)
				if name != "" {
					components[name] = version
				}
			}
		}
	}
	return components, nil
}

func (s *SBOMScanner) MatchCVEs(packageName, version string) ([]string, error) {
	cmd := exec.Command("grype", fmt.Sprintf("%s:%s", packageName, version), "-o", "json")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("grype: %w", err)
	}
	var result map[string]interface{}
	json.Unmarshal(stdout.Bytes(), &result)
	var cves []string
	if matches, ok := result["matches"].([]interface{}); ok {
		for _, m := range matches {
			if match, ok := m.(map[string]interface{}); ok {
				if vuln, ok := match["vulnerability"].(map[string]interface{}); ok {
					if id, ok := vuln["id"].(string); ok {
						cves = append(cves, id)
					}
				}
			}
		}
	}
	return cves, nil
}
