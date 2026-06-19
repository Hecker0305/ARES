package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ares/engine/internal/audit"
	"github.com/ares/engine/internal/uuid"

	"github.com/ares/engine/internal/report"
	"github.com/ares/engine/internal/scanctx"
	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/store"
	"github.com/ares/engine/internal/verifier"
	"github.com/ares/engine/internal/webserver"
)

type MetricData struct {
	TotalScans         int    `json:"totalScans"`
	ScansDelta         string `json:"scansDelta"`
	CriticalFindings   int    `json:"criticalFindings"`
	CriticalUnresolved int    `json:"criticalUnresolved"`
	TargetsCovered     int    `json:"targetsCovered"`
	TargetProjects     int    `json:"targetProjects"`
	VerifiedRate       int    `json:"verifiedRate"`
	RateLabel          string `json:"rateLabel"`
}

type ActiveScanJSON struct {
	Target   string  `json:"target"`
	Status   string  `json:"status"`
	Progress float64 `json:"progress,omitempty"`
	Phase    string  `json:"phase,omitempty"`
}

type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type VulnCategory struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ScanQueueData struct {
	Running          int `json:"running"`
	Queued           int `json:"queued"`
	CompletedToday   int `json:"completedToday"`
	WorkersAvailable int `json:"workersAvailable"`
	WorkersTotal     int `json:"workersTotal"`
}

type FindingJSON struct {
	ID           string  `json:"id"`
	Title        string  `json:"title"`
	Severity     string  `json:"severity"`
	Endpoint     string  `json:"endpoint"`
	Status       string  `json:"status"`
	Project      string  `json:"project"`
	DiscoveredAt string  `json:"discoveredAt"`
	CVSSScore    float64 `json:"cvssScore,omitempty"`
	CVE          string  `json:"cve,omitempty"`
	ScanID       string  `json:"scan_id,omitempty"`
	Confirmed    bool    `json:"confirmed"`
}

type MITREMappingEntry struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	ID        string `json:"id"`
}

type FindingDetailJSON struct {
	FindingJSON
	Description        string              `json:"description"`
	Impact             string              `json:"impact"`
	Remediation        string              `json:"remediation"`
	PoC                string              `json:"poc"`
	EvidencePath       string              `json:"evidencePath"`
	ExtractionProof    string              `json:"extractionProof"`
	MITREMapping       []MITREMappingEntry `json:"mitreMapping"`
	ComplianceControls []string            `json:"complianceControls"`
	CVSSVector         string              `json:"cvssVector,omitempty"`
	VerificationChain  []VerificationRound `json:"verificationChain"`
}

type VerificationRound struct {
	Round     int    `json:"round"`
	Result    string `json:"result"`
	Timestamp string `json:"timestamp"`
}

type ProjectJSON struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Target        string            `json:"target"`
	Severity      SeverityBreakdown `json:"severity"`
	TotalFindings int               `json:"totalFindings"`
	LastScan      string            `json:"lastScan"`
	Status        string            `json:"status"`
}

type ScopeEntryJSON struct {
	ID         string   `json:"id"`
	Target     string   `json:"target"`
	Tags       []string `json:"tags"`
	Authorized bool     `json:"authorized"`
}

type SettingsData struct {
	InstanceName      string  `json:"instanceName"`
	MaxWorkers        int     `json:"maxWorkers"`
	EvidenceRetention string  `json:"evidenceRetention"`
	ConfidenceGate    float64 `json:"confidenceGate"`
}

type WebhookSettings struct {
	URL    string                `json:"url"`
	Secret security.SecretString `json:"secret"`
	Events []string              `json:"events"`
}

type LLMModelJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	BaseURL     string `json:"baseUrl"`
	Description string `json:"description"`
	MaxTokens   int    `json:"maxTokens,omitempty"`
	IsDefault   bool   `json:"isDefault,omitempty"`
}

type LLMSettings struct {
	Provider    string         `json:"provider"`
	Model       string         `json:"model"`
	BaseURL     string         `json:"baseURL"`
	ModelID     string         `json:"modelId,omitempty"`
	Models      []LLMModelJSON `json:"models,omitempty"`
	MaxTokens   int            `json:"maxTokens,omitempty"`
	Temperature float64        `json:"temperature,omitempty"`
}

type TeamMember struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type WebRateLimitSettings struct {
	RequestsPerWindow int `json:"requestsPerWindow"`
	WindowSeconds     int `json:"windowSeconds"`
}

type WebDiscordSettings struct {
	WebhookURL      string `json:"webhookUrl"`
	MinimumSeverity string `json:"minimumSeverity"`
}

type WebAgentMailSettings struct {
	Pod    string `json:"pod"`
	APIKey string `json:"apiKey"`
	HasKey bool   `json:"hasApiKey"`
}

type ComplianceReportJSON struct {
	Framework      string `json:"framework"`
	Score          int    `json:"score"`
	ControlsPassed int    `json:"controlsPassed"`
	ControlsFailed int    `json:"controlsFailed"`
	GapsCritical   int    `json:"gapsCritical"`
	GapsHigh       int    `json:"gapsHigh"`
	LastAssessed   string `json:"lastAssessed"`
}

type ComplianceFindingJSON struct {
	Framework   string `json:"framework"`
	ControlID   string `json:"controlId"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	scans := s.scanStore.ListWithTenant(tenantID)
	totalScans := len(scans)
	criticalCount := 0
	criticalUnresolved := 0
	allTargets := make(map[string]bool)

	for _, scan := range scans {
		allTargets[scan.Target] = true
		for _, f := range scan.Findings {
			if strings.EqualFold(f.Severity, "critical") {
				criticalCount++
				if !f.Confirmed {
					criticalUnresolved++
				}
			}
		}
	}

	verifiedCount := 0
	totalFindings := 0
	for _, scan := range scans {
		for _, f := range scan.Findings {
			totalFindings++
			if f.Confirmed {
				verifiedCount++
			}
		}
	}
	verifiedRate := 0
	if totalFindings > 0 {
		verifiedRate = (verifiedCount * 100) / totalFindings
	}

	json.NewEncoder(w).Encode(MetricData{
		TotalScans:         totalScans,
		ScansDelta:         fmt.Sprintf("%d completed", totalScans),
		CriticalFindings:   criticalCount,
		CriticalUnresolved: criticalUnresolved,
		TargetsCovered:     len(allTargets),
		TargetProjects:     1,
		VerifiedRate:       verifiedRate,
		RateLabel:          "Confirmation rate",
	})
}

func (s *Server) handleActiveScans(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	scans := s.scanStore.ListWithTenant(tenantID)
	var active []ActiveScanJSON
	for _, scan := range scans {
		if scan.Status == "running" || scan.Status == "queued" {
			active = append(active, ActiveScanJSON{
				Target:   scan.Target,
				Status:   scan.Status,
				Progress: scan.Progress,
				Phase:    scan.Phase,
			})
		}
	}
	if active == nil {
		active = []ActiveScanJSON{}
	}
	json.NewEncoder(w).Encode(active)
}

func (s *Server) handleRecentCriticals(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	scans := s.scanStore.ListWithTenant(tenantID)
	var findings []FindingJSON
	for _, scan := range scans {
		for _, f := range scan.Findings {
			if strings.EqualFold(f.Severity, "critical") {
				status := "open"
				ep := f.Target
				if e, ok := f.Evidence["endpoint"]; ok && e != "" {
					ep = e
				}
				findings = append(findings, FindingJSON{
					ID:           f.ID,
					Title:        f.Title,
					Severity:     f.Severity,
					Endpoint:     ep,
					Status:       status,
					Project:      extractProject(f.Target),
					DiscoveredAt: f.Timestamp.Format(time.RFC3339),
					CVSSScore:    f.CVSS,
				})
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].DiscoveredAt < findings[j].DiscoveredAt
	})
	if len(findings) > 5 {
		findings = findings[:5]
	}
	if findings == nil {
		findings = []FindingJSON{}
	}
	json.NewEncoder(w).Encode(findings)
}

func (s *Server) handleSeverityBreakdown(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	var breakdown SeverityBreakdown
	for _, scan := range s.scanStore.ListWithTenant(tenantID) {
		for _, f := range scan.Findings {
			switch strings.ToLower(f.Severity) {
			case "critical":
				breakdown.Critical++
			case "high":
				breakdown.High++
			case "medium":
				breakdown.Medium++
			case "low":
				breakdown.Low++
			}
		}
	}
	json.NewEncoder(w).Encode(breakdown)
}

func (s *Server) handleVulnCategories(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	categoryCount := make(map[string]int)
	for _, scan := range s.scanStore.ListWithTenant(tenantID) {
		for _, f := range scan.Findings {
			cat := classifyVuln(f.Title)
			categoryCount[cat]++
		}
	}
	var cats []VulnCategory
	for name, count := range categoryCount {
		cats = append(cats, VulnCategory{Name: name, Count: count})
	}
	sort.Slice(cats, func(i, j int) bool {
		return cats[i].Count > cats[j].Count
	})
	if len(cats) > 5 {
		cats = cats[:5]
	}
	if cats == nil {
		cats = []VulnCategory{}
	}
	json.NewEncoder(w).Encode(cats)
}

func (s *Server) handleScanQueue(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	running := 0
	queued := 0
	completedToday := 0
	now := time.Now()
	for _, scan := range s.scanStore.ListWithTenant(tenantID) {
		switch scan.Status {
		case "running":
			running++
		case "queued":
			queued++
		case "completed":
			if scan.StartTime.Day() == now.Day() &&
				scan.StartTime.Month() == now.Month() &&
				scan.StartTime.Year() == now.Year() {
				completedToday++
			}
		}
	}
	settings := s.persistStore.GetSettings()
	workersTotal := settings.MaxWorkers
	if workersTotal <= 0 {
		workersTotal = 5
	}
	workersAvailable := workersTotal - running
	if workersAvailable < 0 {
		workersAvailable = 0
	}
	json.NewEncoder(w).Encode(ScanQueueData{
		Running:          running,
		Queued:           queued,
		CompletedToday:   completedToday,
		WorkersAvailable: workersAvailable,
		WorkersTotal:     workersTotal,
	})
}

func (s *Server) handleFindingsList(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	var allFindings []FindingJSON
	for _, scan := range s.scanStore.ListWithTenant(tenantID) {
		for _, f := range scan.Findings {
			if !f.Confirmed {
				continue
			}
			status := "open"
			ep := f.Target
			if e, ok := f.Evidence["endpoint"]; ok && e != "" {
				ep = e
			}
			allFindings = append(allFindings, FindingJSON{
				ID:           f.ID,
				Title:        f.Title,
				Severity:     f.Severity,
				Endpoint:     ep,
				Status:       status,
				Project:      extractProject(f.Target),
				DiscoveredAt: f.Timestamp.Format(time.RFC3339),
				CVSSScore:    f.CVSS,
				ScanID:       scan.ID,
			})
		}
	}
	if allFindings == nil {
		allFindings = []FindingJSON{}
	}

	offset := 0
	limit := len(allFindings)
	if o := r.URL.Query().Get("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if offset < 0 {
		offset = 0
	}
	if limit < 0 {
		limit = 0
	}

	total := len(allFindings)
	if offset >= total {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":   []FindingJSON{},
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
		return
	}
	end := offset + limit
	if end > total {
		end = total
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":   allFindings[offset:end],
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) handleFindingDetail(w http.ResponseWriter, r *http.Request, id string) {
	tenantID := s.getTenantID(r)
	for _, scan := range s.scanStore.ListWithTenant(tenantID) {
		for _, f := range scan.Findings {
			if f.ID == id {
				ep := f.Target
				if e, ok := f.Evidence["endpoint"]; ok && e != "" {
					ep = e
				}
				impact := f.Evidence["impact"]
				if impact == "" {
					impact = "Potential security impact requiring investigation"
				}
				remediation := f.Evidence["remediation"]
				if remediation == "" {
					remediation = "Apply security patches and follow best practices"
				}
				var mitre []MITREMappingEntry
				for _, tag := range f.MitreTags {
					entry := MITREMappingEntry{ID: tag}
					if parts := strings.SplitN(tag, ":", 2); len(parts) == 2 {
						entry.Tactic = parts[0]
						entry.Technique = parts[1]
					}
					mitre = append(mitre, entry)
				}
				detail := FindingDetailJSON{
					FindingJSON: FindingJSON{
						ID:           f.ID,
						Title:        f.Title,
						Severity:     f.Severity,
						Endpoint:     ep,
						Status:       "open",
						Project:      extractProject(f.Target),
						DiscoveredAt: f.Timestamp.Format(time.RFC3339),
						CVSSScore:    f.CVSS,
						ScanID:       scan.ID,
					},
					Description:       f.Description,
					Impact:            impact,
					Remediation:       remediation,
					PoC:               f.Evidence["poc"],
					EvidencePath:      f.Evidence["path"],
					ExtractionProof:   f.Evidence["proof"],
					MITREMapping:      mitre,
					CVSSVector:        fmt.Sprintf("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
					VerificationChain: []VerificationRound{},
				}
				json.NewEncoder(w).Encode(detail)
				return
			}
		}
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (s *Server) handleFindingValidate(w http.ResponseWriter, r *http.Request, id string) {
	tenantID := s.getTenantID(r)
	if s.verifierEngine == nil {
		http.Error(w, "verifier engine not available", http.StatusInternalServerError)
		return
	}

	var finding *Finding
	var scanID string
	for _, scan := range s.scanStore.ListWithTenant(tenantID) {
		for _, f := range scan.Findings {
			if f.ID == id {
				finding = &f
				scanID = scan.ID
				break
			}
		}
		if finding != nil {
			break
		}
	}

	if finding == nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}

	var req struct {
		Method         string `json:"method"`
		Payload        string `json:"payload"`
		ExpectedOutput string `json:"expectedOutput"`
		ForceRevalid   bool   `json:"forceRevalidate"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.Method == "" {
		req.Method = "replay"
	}

	method := verifier.VerificationMethod(req.Method)
	verReq := verifier.VerificationRequest{
		ID:             finding.ID,
		VulnType:       finding.Type,
		Target:         finding.Target,
		Payload:        req.Payload,
		ExpectedOutput: req.ExpectedOutput,
		Method:         method,
		MaxAttempts:    3,
		Threshold:      0.8,
		Metadata: map[string]string{
			"scan_id":  scanID,
			"severity": finding.Severity,
		},
	}

	result := s.verifierEngine.Verify(verReq)

	audit.LogStructured("system", "finding.validate", "finding", finding.ID, string(result.Verdict),
		audit.WithDetail("method", string(req.Method)),
		audit.WithDetail("confidence", result.Confidence),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"findingId":    finding.ID,
		"scanId":       scanID,
		"verdict":      result.Verdict,
		"method":       result.Method,
		"confidence":   result.Confidence,
		"evidence":     result.Evidence,
		"reproducible": result.Reproducible,
		"attempts":     result.Attempts,
		"duration":     result.Duration.String(),
		"timestamp":    result.Timestamp.Format(time.RFC3339),
	})
}

func (s *Server) handleFindingStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tenantID := s.getTenantID(r)
	for _, scan := range s.scanStore.ListWithTenant(tenantID) {
		scan.mu.Lock()
		for i := range scan.Findings {
			if scan.Findings[i].ID == req.ID {
				scan.Findings[i].Type = req.Status
				scan.mu.Unlock()
				json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
				return
			}
		}
		scan.mu.Unlock()
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	projectMap := make(map[string]*ProjectJSON)
	for _, scan := range s.scanStore.ListWithTenant(tenantID) {
		proj := extractProject(scan.Target)
		if _, ok := projectMap[proj]; !ok {
			projectMap[proj] = &ProjectJSON{
				ID:     fmt.Sprintf("proj-%d", len(projectMap)+1),
				Name:   proj,
				Target: scan.Target,
				Status: "active",
			}
		}
		p := projectMap[proj]
		p.TotalFindings += len(scan.Findings)
		for _, f := range scan.Findings {
			switch strings.ToLower(f.Severity) {
			case "critical":
				p.Severity.Critical++
			case "high":
				p.Severity.High++
			case "medium":
				p.Severity.Medium++
			case "low":
				p.Severity.Low++
			}
		}
		if scan.StartTime.After(time.Now().Add(-24*time.Hour)) || p.LastScan == "" {
			p.LastScan = formatDurationAgo(scan.StartTime)
		}
	}
	var projects []*ProjectJSON
	for _, p := range projectMap {
		projects = append(projects, p)
	}
	if projects == nil {
		projects = []*ProjectJSON{}
	}
	json.NewEncoder(w).Encode(projects)
}

func (s *Server) handleScopeList(w http.ResponseWriter, r *http.Request) {
	scopes := s.persistStore.ListScopes()
	var out []ScopeEntryJSON
	for _, s := range scopes {
		out = append(out, ScopeEntryJSON{
			ID:         s.ID,
			Target:     s.Target,
			Tags:       s.Tags,
			Authorized: s.Authorized,
		})
	}
	if out == nil {
		out = buildScopeFromScans(s.scanStore.List())
	}
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleScopeAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string   `json:"target"`
		Tags   []string `json:"tags"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	entry, err := s.persistStore.AddScope(req.Target, req.Tags)
	if err != nil {
		http.Error(w, "failed to add scope entry", http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(ScopeEntryJSON{
		ID:         entry.ID,
		Target:     entry.Target,
		Tags:       entry.Tags,
		Authorized: entry.Authorized,
	})
}

func (s *Server) handleScopeDelete(w http.ResponseWriter, r *http.Request, id string) {
	if s.persistStore.DeleteScope(id) {
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	} else {
		http.Error(w, "scope not found", http.StatusNotFound)
	}
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	settings := s.persistStore.GetSettings()
	json.NewEncoder(w).Encode(SettingsData{
		InstanceName:      settings.InstanceName,
		MaxWorkers:        settings.MaxWorkers,
		EvidenceRetention: settings.EvidenceRetention,
		ConfidenceGate:    settings.ConfidenceGate,
	})
}

func (s *Server) handleSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var req SettingsData
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	settings := store.AppSettings{
		InstanceName:      req.InstanceName,
		MaxWorkers:        req.MaxWorkers,
		EvidenceRetention: req.EvidenceRetention,
		ConfidenceGate:    req.ConfidenceGate,
	}
	s.persistStore.SaveSettings(settings)
	json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
}

func defaultSIEMPresets() []store.SIEMPreset {
	return []store.SIEMPreset{
		{ID: "sentinel", Name: "Microsoft Sentinel", Type: "sentinel", Endpoint: "https://<workspace-id>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01", APIMode: "azure-log-analytics", Icon: "azure", DocsURL: "https://learn.microsoft.com/sentinel/", Enabled: false},
		{ID: "splunk", Name: "Splunk HEC", Type: "splunk", Endpoint: "https://<splunk-host>:8088/services/collector", APIMode: "hec-token", Icon: "splunk", DocsURL: "https://docs.splunk.com/Documentation/Splunk/latest/Data/HEC", Enabled: false},
		{ID: "elastic", Name: "Elasticsearch", Type: "elastic", Endpoint: "https://<elastic-host>:9200/ares-vulns/_doc", APIMode: "api-key", Icon: "elastic", DocsURL: "https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html", Enabled: false},
		{ID: "datadog", Name: "Datadog", Type: "datadog", Endpoint: "https://api.datadoghq.com", APIMode: "api-key", Icon: "datadog", DocsURL: "https://docs.datadoghq.com/api/latest/events/", Enabled: false},
		{ID: "qradar", Name: "IBM QRadar", Type: "cef", Endpoint: "https://<qradar-host>:514", APIMode: "syslog-cef", Icon: "ibm", DocsURL: "https://www.ibm.com/qradar", Enabled: false},
	}
}

func (s *Server) handleWebhookSettingsGet(w http.ResponseWriter, r *http.Request) {
	wh := s.persistStore.GetWebhook()
	presets := wh.SIEMPresets
	if len(presets) == 0 {
		presets = defaultSIEMPresets()
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"url":    wh.URL,
		"secret": wh.Secret,
		"events": wh.Events,
	})
}

func (s *Server) handleWebhookSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL    string                `json:"url"`
		Secret security.SecretString `json:"secret"`
		Events []string              `json:"events"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.URL != "" {
		if err := security.ValidateURL(req.URL); err != nil {
			http.Error(w, "invalid webhook URL: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	s.persistStore.SaveWebhook(store.WebhookSettings{
		URL:    req.URL,
		Secret: req.Secret,
		Events: req.Events,
	})
	json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
}

func (s *Server) handleSIEMPresets(w http.ResponseWriter, r *http.Request) {
	presets := defaultSIEMPresets()
	if r.Method == http.MethodPut {
		var req struct {
			Presets []store.SIEMPreset `json:"presets"`
		}
		if requireJSONContentType(w, r) {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil && len(req.Presets) > 0 {
				presets = req.Presets
				wh := s.persistStore.GetWebhook()
				wh.SIEMPresets = presets
				s.persistStore.SaveWebhook(wh)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"presets":       presets,
		"activePresets": countEnabledPresets(presets),
	})
}

func countEnabledPresets(presets []store.SIEMPreset) int {
	count := 0
	for _, p := range presets {
		if p.Enabled {
			count++
		}
	}
	return count
}

func (s *Server) handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	wh := s.persistStore.GetWebhook()
	if wh.URL == "" {
		json.NewEncoder(w).Encode(map[string]string{"status": "no_webhook_configured"})
		return
	}
	if err := security.ValidateURL(wh.URL); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "failed", "error": "invalid webhook URL"})
		return
	}
	reqBody, err := json.Marshal(map[string]interface{}{
		"content": "🔍 Ares Engine: Webhook test successful",
	})
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "failed", "error": "failed to marshal request"})
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(wh.URL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "failed", "error": "connection failed"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		json.NewEncoder(w).Encode(map[string]string{"status": "test_sent"})
	} else {
		json.NewEncoder(w).Encode(map[string]string{"status": "failed", "error": fmt.Sprintf("HTTP %d", resp.StatusCode)})
	}
}

func defaultModelRegistry() []store.LLMModel {
	return []store.LLMModel{
		{ID: "openai-gpt4o", Name: "GPT-4o", Provider: "openai", BaseURL: "https://api.openai.com/v1", Description: "OpenAI GPT-4o — best balance of speed and reasoning", MaxTokens: 128000, IsDefault: true},
		{ID: "openai-gpt45", Name: "GPT-4.5", Provider: "openai", BaseURL: "https://api.openai.com/v1", Description: "OpenAI GPT-4.5 — highest reasoning capability", MaxTokens: 128000},
		{ID: "openai-o3", Name: "o3", Provider: "openai", BaseURL: "https://api.openai.com/v1", Description: "OpenAI o3 — advanced reasoning model", MaxTokens: 200000},
		{ID: "anthropic-claude35", Name: "Claude 3.5 Sonnet", Provider: "anthropic", BaseURL: "https://api.anthropic.com/v1", Description: "Anthropic Claude 3.5 Sonnet", MaxTokens: 200000},
		{ID: "anthropic-claude4", Name: "Claude 4 Opus", Provider: "anthropic", BaseURL: "https://api.anthropic.com/v1", Description: "Anthropic Claude 4 Opus", MaxTokens: 200000},
		{ID: "google-gemini2", Name: "Gemini 2.0 Flash", Provider: "google", BaseURL: "https://generativelanguage.googleapis.com/v1beta", Description: "Google Gemini 2.0 Flash", MaxTokens: 1048576},
		{ID: "google-gemini2-pro", Name: "Gemini 2.5 Pro", Provider: "google", BaseURL: "https://generativelanguage.googleapis.com/v1beta", Description: "Google Gemini 2.5 Pro", MaxTokens: 1048576},
		{ID: "deepseek-v4", Name: "DeepSeek V4", Provider: "deepseek", BaseURL: "https://api.deepseek.com/v1", Description: "DeepSeek V4 — powerful reasoning", MaxTokens: 128000},
		{ID: "ollama-qwen3", Name: "Qwen3 (Local)", Provider: "ollama", BaseURL: "http://localhost:11434/v1", Description: "Local Qwen3 via Ollama", MaxTokens: 128000},
		{ID: "ollama-llama3", Name: "Llama 3 (Local)", Provider: "ollama", BaseURL: "http://localhost:11434/v1", Description: "Local Llama 3 via Ollama", MaxTokens: 128000},
		{ID: "custom", Name: "Custom Endpoint", Provider: "custom", BaseURL: "", Description: "Any OpenAI-compatible endpoint", MaxTokens: 128000},
	}
}

func (s *Server) handleLLMSettingsGet(w http.ResponseWriter, r *http.Request) {
	llm := s.persistStore.GetLLM()
	storeModels := llm.Models
	if len(storeModels) == 0 {
		storeModels = defaultModelRegistry()
	}
	models := make([]LLMModelJSON, len(storeModels))
	for i, m := range storeModels {
		models[i] = LLMModelJSON{
			ID:          m.ID,
			Name:        m.Name,
			Provider:    m.Provider,
			BaseURL:     m.BaseURL,
			Description: m.Description,
			MaxTokens:   m.MaxTokens,
			IsDefault:   m.IsDefault,
		}
	}
	json.NewEncoder(w).Encode(LLMSettings{
		Provider:    llm.Provider,
		Model:       llm.Model,
		BaseURL:     llm.BaseURL,
		Models:      models,
		ModelID:     llm.ModelID,
		MaxTokens:   llm.MaxTokens,
		Temperature: llm.Temperature,
	})
}

func (s *Server) handleLLMSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var req LLMSettings
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	llmSettings := store.LLMSettings{
		Provider:    req.Provider,
		Model:       req.Model,
		BaseURL:     req.BaseURL,
		ModelID:     req.ModelID,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}
	if len(req.Models) > 0 {
		storeModels := make([]store.LLMModel, len(req.Models))
		for i, m := range req.Models {
			storeModels[i] = store.LLMModel{
				ID:          m.ID,
				Name:        m.Name,
				Provider:    m.Provider,
				BaseURL:     m.BaseURL,
				Description: m.Description,
				MaxTokens:   m.MaxTokens,
				IsDefault:   m.IsDefault,
			}
		}
		llmSettings.Models = storeModels
	}
	s.persistStore.SaveLLM(llmSettings)
	json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
}

func (s *Server) handleRateLimitGet(w http.ResponseWriter, r *http.Request) {
	rl := s.persistStore.GetRateLimit()
	json.NewEncoder(w).Encode(WebRateLimitSettings{
		RequestsPerWindow: rl.RequestsPerWindow,
		WindowSeconds:     rl.WindowSeconds,
	})
}

func (s *Server) handleRateLimitUpdate(w http.ResponseWriter, r *http.Request) {
	var req WebRateLimitSettings
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.persistStore.SaveRateLimit(store.RateLimitSettings{
		RequestsPerWindow: req.RequestsPerWindow,
		WindowSeconds:     req.WindowSeconds,
	})
	json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
}

func (s *Server) handleDiscordGet(w http.ResponseWriter, r *http.Request) {
	d := s.persistStore.GetDiscord()
	json.NewEncoder(w).Encode(WebDiscordSettings{
		WebhookURL:      d.WebhookURL,
		MinimumSeverity: d.MinimumSeverity,
	})
}

func (s *Server) handleDiscordUpdate(w http.ResponseWriter, r *http.Request) {
	var req WebDiscordSettings
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.persistStore.SaveDiscord(store.DiscordSettings{
		WebhookURL:      req.WebhookURL,
		MinimumSeverity: req.MinimumSeverity,
	})
	json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
}

func (s *Server) handleAgentMailGet(w http.ResponseWriter, r *http.Request) {
	a := s.persistStore.GetAgentMail()
	out := WebAgentMailSettings{
		Pod:    a.Pod,
		HasKey: a.HasKey,
	}
	if a.HasKey {
		out.APIKey = "••••••••"
	}
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleAgentMailUpdate(w http.ResponseWriter, r *http.Request) {
	var req WebAgentMailSettings
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	existing := s.persistStore.GetAgentMail()
	apiKey := existing.APIKey
	if req.APIKey != "" && req.APIKey != "••••••••" {
		apiKey = security.NewSecret(req.APIKey)
	}
	s.persistStore.SaveAgentMail(store.AgentMailSettings{
		Pod:    req.Pod,
		APIKey: apiKey,
		HasKey: apiKey.String() != "",
	})
	json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
}

func (s *Server) handleTeamList(w http.ResponseWriter, r *http.Request) {
	members := s.persistStore.ListTeam()
	type teamMemberOut struct {
		Name       string `json:"name"`
		Role       string `json:"role"`
		LastActive string `json:"lastActive"`
	}
	var out []teamMemberOut
	for _, m := range members {
		out = append(out, teamMemberOut{
			Name:       m.Email,
			Role:       m.Role,
			LastActive: m.LastActive,
		})
	}
	if out == nil {
		out = []teamMemberOut{{Name: "admin@ares.local", Role: "admin", LastActive: "Now"}}
	}
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleTeamInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	member, err := s.persistStore.AddTeamMember(req.Email, req.Role)
	if err != nil {
		http.Error(w, "failed to add team member", http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "invited",
		"email":  member.Email,
		"role":   member.Role,
	})
}

func (s *Server) handleComplianceReports(w http.ResponseWriter, r *http.Request) {
	findings := s.scanStore.AllFindings()
	frameworks := []string{
		"NIST CSF 2.0", "NIST SP 800-53", "NIST 800-171",
		"ISO 27001:2022", "PCI DSS v4.0", "SOC 2 Type II",
		"HIPAA", "GDPR", "CMMC Level 1-3",
		"EU DORA", "NIS 2", "TISAX",
		"EU AI Act", "ACSC Essential Eight",
	}
	var reports []ComplianceReportJSON
	for _, fw := range frameworks {
		total := len(findings)
		passed := 0
		failed := 0
		critical := 0
		high := 0
		for _, f := range findings {
			if strings.EqualFold(f.Severity, "critical") || strings.EqualFold(f.Severity, "high") {
				failed++
				if strings.EqualFold(f.Severity, "critical") {
					critical++
				} else {
					high++
				}
			} else {
				passed++
			}
		}
		score := 0
		if total > 0 {
			score = (passed * 100) / total
		} else {
			score = 100
		}
		reports = append(reports, ComplianceReportJSON{
			Framework:      fw,
			Score:          score,
			ControlsPassed: passed,
			ControlsFailed: failed,
			GapsCritical:   critical,
			GapsHigh:       high,
			LastAssessed:   time.Now().Add(-time.Duration(len(reports)*24) * time.Hour).Format(time.RFC3339),
		})
	}
	json.NewEncoder(w).Encode(reports)
}

func (s *Server) handleComplianceFindings(w http.ResponseWriter, r *http.Request) {
	framework := r.URL.Query().Get("framework")
	if framework == "" {
		framework = "NIST CSF 2.0"
	}
	controlMap := map[string]string{
		"sqli":    "PR.AC-1",
		"xss":     "PR.AC-4",
		"ssrf":    "PR.AC-6",
		"idor":    "PR.AC-3",
		"auth":    "PR.AC-1",
		"secret":  "PR.DS-1",
		"csrf":    "PR.AC-7",
		"upload":  "PR.AC-5",
		"rce":     "PR.AC-2",
		"default": "PR.AC-9",
	}
	var findings []ComplianceFindingJSON
	for _, f := range s.scanStore.AllFindings() {
		ctrlID := controlMap["default"]
		for key, ctrl := range controlMap {
			if strings.Contains(strings.ToLower(f.Title), key) || strings.Contains(strings.ToLower(f.Type), key) {
				ctrlID = ctrl
				break
			}
		}
		findings = append(findings, ComplianceFindingJSON{
			Framework:   framework,
			ControlID:   ctrlID,
			Status:      mapFindingStatus(f),
			Severity:    f.Severity,
			Description: f.Title,
			Evidence:    f.Description,
			Remediation: generateRemediation(f.Type),
		})
	}
	if findings == nil {
		findings = []ComplianceFindingJSON{}
	}
	json.NewEncoder(w).Encode(findings)
}

func mapFindingStatus(f Finding) string {
	if f.Confirmed {
		return "verified"
	}
	return "open"
}

func generateRemediation(vulnType string) string {
	remediations := map[string]string{
		"sqli":    "Use parameterized queries, implement input validation, apply least-privilege DB access",
		"xss":     "Implement CSP headers, sanitize user input, use output encoding",
		"ssrf":    "Validate and whitelist URLs, block internal IPs, use allowlists",
		"idor":    "Implement proper authorization checks on all object references",
		"auth":    "Enforce MFA, implement rate limiting, use secure session management",
		"secret":  "Rotate exposed secrets, use secret management tools, scan code for leaks",
		"csrf":    "Implement anti-CSRF tokens, validate SameSite cookie attributes",
		"upload":  "Validate file types, scan uploads, store outside webroot",
		"rce":     "Sanitize all inputs, use allowlists, avoid dynamic code execution",
		"default": "Apply security controls per framework requirements and conduct regular audits",
	}
	for key, remediation := range remediations {
		if strings.Contains(strings.ToLower(vulnType), key) {
			return remediation
		}
	}
	return remediations["default"]
}

func (s *Server) handleReportExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Format string `json:"format"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "exported",
		"format":   req.Format,
		"url":      fmt.Sprintf("/exports/report.%s", req.Format),
		"findings": len(s.scanStore.List()),
	})
}

func (s *Server) handleScanPresets(w http.ResponseWriter, r *http.Request) {
	type phaseInfo struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	phases := make([]phaseInfo, len(scanctx.AllPhases22))
	for i, p := range scanctx.AllPhases22 {
		phases[i] = phaseInfo{ID: p.Number, Name: p.Label, Description: p.Description}
	}
	type scanModeInfo struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	modes := make([]scanModeInfo, len(scanctx.ScanModes))
	for i, m := range scanctx.ScanModes {
		modes[i] = scanModeInfo{ID: string(m.ID), Name: m.Label, Description: m.Description}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"presets": []map[string]interface{}{
			{"name": "Quick Scan", "description": "Surface-level recon & common vulns in <5 min", "phases": []string{"reconnaissance", "injection_testing"}, "scan_mode": "single"},
			{"name": "Deep Scan", "description": "Full methodology: recon → exploit → report", "phases": []string{"reconnaissance", "manual_vuln_discovery", "directory_discovery", "injection_testing", "exploit_verification", "final_report"}, "scan_mode": "single"},
			{"name": "Authenticated Scan", "description": "Post-auth testing with session/cookie", "phases": []string{"auth_session_testing", "injection_testing", "idor_access_control", "exploit_verification"}, "scan_mode": "dast"},
			{"name": "API Scan", "description": "REST/GraphQL fuzzing & schema analysis", "phases": []string{"api_graphql", "injection_testing", "ssrf_testing", "exploit_verification"}, "scan_mode": "single"},
		},
		"phases":    phases,
		"scanModes": modes,
	})
}

func (s *Server) handleUploadTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	contentType := r.Header.Get("Content-Type")
	var targets []string

	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "bad multipart form", http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "missing file field", http.StatusBadRequest)
			return
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read file: %v", err), http.StatusInternalServerError)
			return
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	} else {
		var req struct {
			Targets []string `json:"targets"`
		}
		if !requireJSONContentType(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		targets = req.Targets
	}

	if len(targets) == 0 {
		http.Error(w, "no targets provided", http.StatusBadRequest)
		return
	}

	scanIDs := make([]string, 0, len(targets))
	for _, target := range targets {
		if err := security.ValidateTarget(target); err != nil {
			http.Error(w, fmt.Sprintf("invalid target %q: %v", target, err), http.StatusBadRequest)
			return
		}
		scanID := s.runScan(target)
		scanIDs = append(scanIDs, scanID)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "started",
		"scan_ids": scanIDs,
		"count":    len(scanIDs),
	})
}

func (s *Server) handleUploadLogo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
	if err := r.ParseMultipartForm(5 << 20); err != nil {
		http.Error(w, "file too large or invalid multipart", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("logo")
	if err != nil {
		http.Error(w, "missing logo file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	ext := ".png"
	if header.Filename != "" {
		if idx := strings.LastIndex(header.Filename, "."); idx >= 0 {
			candidate := header.Filename[idx:]
			// sanitize: only allow lowercase alphanumeric extensions with a single dot
			if len(candidate) <= 6 && len(candidate) >= 2 {
				clean := strings.ToLower(candidate)
				valid := true
				for i, c := range clean {
					if i == 0 && c != '.' {
						valid = false
						break
					}
					if i > 0 && !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
						valid = false
						break
					}
				}
				if valid {
					ext = clean
				}
			}
		}
	}
	logoDir := filepath.Join(s.cfg.StoreDir, "logos")
	os.MkdirAll(logoDir, 0700)
	logoPath := filepath.Join(logoDir, "brand"+ext)
	dst, err := os.OpenFile(logoPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		http.Error(w, "failed to save logo", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "failed to write logo", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{
		"status": "uploaded",
		"path":   logoPath,
	})
}

func (s *Server) handleEnvGet(w http.ResponseWriter, r *http.Request) {
	envVars := map[string]string{
		"ARES_INSTANCE_NAME":      os.Getenv("ARES_INSTANCE_NAME"),
		"ARES_LLM_PROVIDER":       os.Getenv("ARES_LLM_PROVIDER"),
		"ARES_LLM_MODEL":          os.Getenv("ARES_LLM_MODEL"),
		"ARES_LLM_BASE_URL":       os.Getenv("ARES_LLM_BASE_URL"),
		"ARES_WEBHOOK_URL":        os.Getenv("ARES_WEBHOOK_URL"),
		"ARES_ADMIN_PASSWORD":     "",
		"ARES_MAX_WORKERS":        os.Getenv("ARES_MAX_WORKERS"),
		"ARES_EVIDENCE_RETENTION": os.Getenv("ARES_EVIDENCE_RETENTION"),
		"ARES_CONFIDENCE_GATE":    os.Getenv("ARES_CONFIDENCE_GATE"),
		"ARES_DISCORD_WEBHOOK":    os.Getenv("ARES_DISCORD_WEBHOOK"),
		"ARES_PROXY_URLS":         os.Getenv("ARES_PROXY_URLS"),
	}
	// overlay persisted overrides
	if s.envStore != nil {
		for k, v := range s.envStore.GetAll() {
			envVars[k] = v
		}
	}
	// redact secrets
	for _, secretKey := range []string{"ARES_ADMIN_PASSWORD", "ARES_ENCRYPTION_KEY", "ARES_API_KEY"} {
		if envVars[secretKey] != "" {
			envVars[secretKey] = "********"
		}
	}
	json.NewEncoder(w).Encode(envVars)
}

func (s *Server) handleEnvUpdate(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	secrets := map[string]bool{"ARES_ADMIN_PASSWORD": true, "ARES_ENCRYPTION_KEY": true, "ARES_API_KEY": true}
	for k, v := range req {
		if secrets[k] {
			if v != "********" {
				if s.envStore != nil {
					s.envStore.Set(k, v)
				}
			}
			continue
		}
		if s.envStore != nil {
			s.envStore.Set(k, v)
		}
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
}

func (s *Server) handleQueueStatus(w http.ResponseWriter, r *http.Request) {
	running := 0
	queued := 0
	completedToday := 0
	now := time.Now()
	for _, scan := range s.scanStore.List() {
		switch scan.Status {
		case "running":
			running++
		case "queued":
			queued++
		case "completed":
			if scan.StartTime.Day() == now.Day() &&
				scan.StartTime.Month() == now.Month() &&
				scan.StartTime.Year() == now.Year() {
				completedToday++
			}
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"running":        running,
		"queued":         queued,
		"completedToday": completedToday,
		"total":          running + queued,
		"status":         "operational",
	})
}

func (s *Server) handleQueueResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ScanID string `json:"scan_id"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.ScanID != "" && s.scanControls != nil {
		s.scanControls.ResumeScan(req.ScanID)
		json.NewEncoder(w).Encode(map[string]string{"status": "resumed", "scan_id": req.ScanID})
		return
	}
	// Resume all queued scans
	for _, scan := range s.scanStore.List() {
		if scan.Status == "queued" && s.scanControls != nil {
			s.scanControls.ResumeScan(scan.ID)
		}
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "queue_resumed"})
}

func (s *Server) handleQueueClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cleared := 0
	for _, scan := range s.scanStore.List() {
		if scan.Status == "queued" {
			s.scanStore.Delete(scan.ID)
			cleared++
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "cleared",
		"cleared": cleared,
	})
}

func (s *Server) handleInstancePause(w http.ResponseWriter, r *http.Request, id string) {
	if s.scanControls != nil {
		s.scanControls.PauseScan(id)
	}
	scan := s.scanStore.Get(id)
	if scan != nil {
		scan.SetStatus("paused")
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "paused", "id": id})
}

func (s *Server) handleInstanceResume(w http.ResponseWriter, r *http.Request, id string) {
	if s.scanControls != nil {
		s.scanControls.ResumeScan(id)
	}
	scan := s.scanStore.Get(id)
	if scan != nil {
		scan.SetStatus("running")
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "resumed", "id": id})
}

func (s *Server) handleInstanceRestart(w http.ResponseWriter, r *http.Request, id string) {
	scan := s.scanStore.Get(id)
	if scan != nil {
		scan.SetStatus("restarting")
		scan.SetPhase("initializing")
	}
	restartScanID := uuid.New()
	if scan != nil {
		if fn := s.getRunScanFn(); fn != nil {
			s.UpdateScanProgress(restartScanID, "running", "restarting", 0)
			go func() {
				fn(restartScanID, scan.Target, nil)
			}()
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "restarted",
		"new_scan_id": restartScanID,
	})
}

// helpers

func extractProject(target string) string {
	if strings.Contains(target, ".") {
		parts := strings.Split(target, ".")
		if len(parts) >= 2 {
			name := parts[len(parts)-2]
			if len(name) > 0 {
				return strings.ToUpper(name[:1]) + name[1:] + " Corp"
			}
		}
	}
	return "Default Project"
}

func formatDurationAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func classifyVuln(title string) string {
	lower := strings.ToLower(title)
	switch {
	case strings.Contains(lower, "sql") || strings.Contains(lower, "injection") || strings.Contains(lower, "sqli"):
		return "Injection (SQLi / CMDi)"
	case strings.Contains(lower, "xss") || strings.Contains(lower, "cross-site"):
		return "XSS"
	case strings.Contains(lower, "ssrf"):
		return "SSRF"
	case strings.Contains(lower, "idor") || strings.Contains(lower, "access control") || strings.Contains(lower, "auth"):
		return "Broken access control"
	case strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "key"):
		return "Exposed secrets"
	default:
		return "Other"
	}
}

func buildScopeFromScans(scans []*ScanSession) []ScopeEntryJSON {
	targets := make(map[string]bool)
	for _, scan := range scans {
		targets[scan.Target] = true
	}
	var entries []ScopeEntryJSON
	i := 0
	for t := range targets {
		i++
		entries = append(entries, ScopeEntryJSON{
			ID:         fmt.Sprintf("scope-%d", i),
			Target:     t,
			Tags:       []string{"auto-detected"},
			Authorized: true,
		})
	}
	if entries == nil {
		entries = []ScopeEntryJSON{}
	}
	return entries
}

func resolvePhaseIDs(names []string) []string {
	phaseMap := make(map[string]string)
	for _, p := range scanctx.AllPhases22 {
		phaseMap[strings.ToLower(p.Label)] = string(p.ID)
		phaseMap[strings.ToLower(string(p.ID))] = string(p.ID)
	}
	seen := make(map[string]bool)
	var result []string
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		if id, ok := phaseMap[key]; ok && !seen[id] {
			result = append(result, id)
			seen[id] = true
		}
	}
	return result
}

func (s *Server) handleScanSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Target         string            `json:"target"`
		Targets        []string          `json:"targets"`
		Preset         string            `json:"preset"`
		ScanProfile    string            `json:"scanProfile"`
		Workers        int               `json:"workers"`
		Phases         []string          `json:"phases"`
		ScanMode       string            `json:"scanMode"`
		EnvVars        map[string]string `json:"envVars"`
		OutOfScope     []string          `json:"outOfScope"`
		ResourceLimits map[string]int    `json:"resourceLimits"`
		AuthorizedBy   string            `json:"authorized_by"`
		Authorization  string            `json:"authorization"`
		Credentials    *CredentialConfig `json:"credentials,omitempty"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	targets := req.Targets
	if req.Target != "" {
		if len(targets) == 0 || targets[0] != req.Target {
			targets = append(targets, req.Target)
		}
	}
	if len(targets) == 0 {
		http.Error(w, "target or targets required", http.StatusBadRequest)
		return
	}

	scanMode := req.ScanMode
	if scanMode == "" {
		scanMode = "normal"
	}

	tenantID := s.getTenantID(r)

	if err := s.checkScanQuota(tenantID); err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	scanID := uuid.New()
	scan := &ScanSession{
		ID:          scanID,
		Target:      targets[0],
		StartTime:   time.Now(),
		Status:      "queued",
		Phase:       "initializing",
		Progress:    0,
		Findings:    make([]Finding, 0),
		Events:      make([]Event, 0),
		Credentials: req.Credentials,
	}
	s.scanStore.AddWithTenant(tenantID, scan)
	s.usageTracker.RecordScanStart(tenantID, scanID)

	phases := resolvePhaseIDs(req.Phases)
	if len(phases) == 0 {
		for _, p := range scanctx.AllPhases22 {
			if p.DefaultOn {
				phases = append(phases, string(p.ID))
			}
		}
	}

	s.Push(scanID, "SCAN_START", fmt.Sprintf("Scan queued for %d target(s), mode=%s, phases=%d", len(targets), scanMode, len(phases)))

	if fn := s.getRunScanFn(); fn != nil {
		s.UpdateScanProgress(scanID, "running", "initializing", 0)
		sem := make(chan struct{}, 5)
		for _, t := range targets {
			sem <- struct{}{}
			targetScanID := uuid.New()
			go func(target, sid string) {
				defer func() { <-sem }()
				fn(sid, target, phases)
			}(t, targetScanID)
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "queued",
		"scan_id":        scanID,
		"scan_mode":      scanMode,
		"phases":         phases,
		"targets":        targets,
		"authorized_by":  req.AuthorizedBy,
		"authorized":     req.Authorization != "",
		"authenticated":  req.Credentials != nil,
	})
}

func (s *Server) handleLiveWebSocket(w http.ResponseWriter, r *http.Request) {
	var upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	var writeMu sync.Mutex
	writeDone := make(chan struct{})
	closeConn := func() {
		writeMu.Lock()
		conn.Close()
		writeMu.Unlock()
	}

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				writeMu.Lock()
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					writeMu.Unlock()
					closeConn()
					return
				}
				writeMu.Unlock()
			case <-r.Context().Done():
				return
			case <-writeDone:
				return
			}
		}
	}()

	sseCl := &webserver.SSEClient{
		Ch:   make(chan webserver.Event, 200),
		Done: make(chan struct{}),
	}
	s.Server.RegisterClient(sseCl)

	go func() {
		defer func() {
			writeMu.Lock()
			conn.Close()
			writeMu.Unlock()
			close(writeDone)
		}()
		for {
			select {
			case ev, ok := <-sseCl.Ch:
				if !ok {
					return
				}
				wsEvent := map[string]interface{}{
					"timestamp":   ev.Timestamp,
					"instance_id": ev.ScanID,
					"type":        ev.Type,
					"content":     ev.Message,
				}
				data, err := json.Marshal(wsEvent)
				if err != nil {
					continue
				}
				writeMu.Lock()
				err = conn.WriteMessage(websocket.TextMessage, data)
				writeMu.Unlock()
				if err != nil {
					return
				}
			case <-r.Context().Done():
				return
			case <-sseCl.Done:
				return
			}
		}
	}()

	userID, _ := r.Context().Value(sessionUserKey).(string)
	if userID == "" {
		userID = "system"
	}

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var msg struct {
			Type    string                 `json:"type"`
			ScanID  string                 `json:"scan_id"`
			Payload map[string]interface{} `json:"payload"`
		}
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "get_status":
			if msg.ScanID != "" {
				scan := s.scanStore.Get(msg.ScanID)
				if scan != nil {
					scan.mu.RLock()
					data, _ := json.Marshal(map[string]interface{}{
						"type":     "scan_status",
						"scan_id":  msg.ScanID,
						"status":   scan.Status,
						"phase":    scan.Phase,
						"progress": scan.Progress,
						"findings": len(scan.Findings),
						"events":   scan.Events,
					})
					scan.mu.RUnlock()
					writeMu.Lock()
					conn.WriteMessage(websocket.TextMessage, data)
					writeMu.Unlock()
				}
			}
		case "pause_scan":
			if msg.ScanID != "" {
				sc := s.scanControls
				if sc != nil {
					sc.PauseScan(msg.ScanID)
					data, _ := json.Marshal(map[string]interface{}{
						"type":    "scan_paused",
						"scan_id": msg.ScanID,
					})
					writeMu.Lock()
					conn.WriteMessage(websocket.TextMessage, data)
					writeMu.Unlock()
				}
			}
		case "resume_scan":
			if msg.ScanID != "" {
				sc := s.scanControls
				if sc != nil {
					sc.ResumeScan(msg.ScanID)
					data, _ := json.Marshal(map[string]interface{}{
						"type":    "scan_resumed",
						"scan_id": msg.ScanID,
					})
					writeMu.Lock()
					conn.WriteMessage(websocket.TextMessage, data)
					writeMu.Unlock()
				}
			}
		}
	}

	s.Server.UnregisterClient(sseCl)
	select {
	case <-sseCl.Done:
	default:
		close(sseCl.Done)
	}
	<-writeDone
}

type compareRequest struct {
	ScanAID string `json:"scan_a_id"`
	ScanBID string `json:"scan_b_id"`
}

func (s *Server) handleScanCompare(w http.ResponseWriter, r *http.Request) {
	var req compareRequest
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.ScanAID == "" || req.ScanBID == "" {
		http.Error(w, "scan_a_id and scan_b_id required", http.StatusBadRequest)
		return
	}

	scanA := s.scanStore.Get(req.ScanAID)
	scanB := s.scanStore.Get(req.ScanBID)
	if scanA == nil || scanB == nil {
		http.Error(w, "one or both scans not found", http.StatusNotFound)
		return
	}

	scanA.mu.RLock()
	reportA := scanToReport(scanA)
	scanA.mu.RUnlock()
	scanB.mu.RLock()
	reportB := scanToReport(scanB)
	scanB.mu.RUnlock()
	differ := report.NewDiffer(report.NewDifferConfig())
	target := scanA.Target
	if target == "" {
		target = scanB.Target
	}
	delta := differ.Compare(reportA, reportB, target)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(delta); err != nil {
		http.Error(w, "failed to encode delta", http.StatusInternalServerError)
	}
}

func scanToReport(s *ScanSession) *report.Report {
	critical, high, medium, low := 0, 0, 0, 0
	var totalCVSS float64
	var confirmedFindings []Finding

	for _, f := range s.Findings {
		confirmedFindings = append(confirmedFindings, f)
		switch strings.ToLower(f.Severity) {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
		totalCVSS += f.CVSS
	}

	duration := ""
	if !s.StartTime.IsZero() {
		d := time.Since(s.StartTime).Round(time.Second)
		if d < 0 {
			d = 0
		}
		duration = d.String()
	}

	avgSeverity := 0.0
	if len(confirmedFindings) > 0 {
		avgSeverity = totalCVSS / float64(len(confirmedFindings))
	}

	coveragePercent := 0.0
	if len(confirmedFindings) > 0 {
		coveragePercent = 100.0
	}

	rpt := &report.Report{
		Title: fmt.Sprintf("Security Scan Report — %s", s.Target),
		Summary: report.ReportSummary{
			TotalTargets:    1,
			TotalFindings:   len(confirmedFindings),
			CriticalCount:   critical,
			HighCount:       high,
			MediumCount:     medium,
			LowCount:        low,
			AvgSeverity:     avgSeverity,
			ScanDuration:    duration,
			CoveragePercent: coveragePercent,
		},
	}
	rpt.GeneratedAt = time.Now()
	rpt.Metadata.TargetScope = []string{s.Target}
	rpt.Metadata.Scanner = "ARES Engine"
	rpt.Metadata.Version = "2.0.0"

	for _, f := range confirmedFindings {
		evidenceStr := ""
		remediationStr := ""
		payloadStr := ""
		if len(f.Evidence) > 0 {
			var parts []string
			for k, v := range f.Evidence {
				if v != "" {
					switch k {
					case "remediation":
						remediationStr = v
					case "poc":
						payloadStr = v
						parts = append(parts, fmt.Sprintf("%s: %s", k, v))
					default:
						parts = append(parts, fmt.Sprintf("%s: %s", k, v))
					}
				}
			}
			evidenceStr = strings.Join(parts, "\n")
		}
		if evidenceStr == "" && f.Description != "" {
			evidenceStr = f.Description
		}

		findingType := f.Type
		if findingType == "" || isSeverityLabel(findingType) {
			findingType = f.Title
			if findingType == "" || isSeverityLabel(findingType) {
				findingType = f.Description
			}
		}

		confidence := 0.9
		if f.Confirmed {
			confidence = 1.0
		}

		rpt.Findings = append(rpt.Findings, report.FindingReport{
			ID:          f.ID,
			Type:        findingType,
			Severity:    f.Severity,
			Target:      f.Target,
			Evidence:    evidenceStr,
			Payload:     payloadStr,
			Remediation: remediationStr,
			Confidence:  confidence,
			MITRE:       f.MitreTags,
			Timestamp:   f.Timestamp.Format(time.RFC3339),
		})
	}
	return rpt
}

func isSeverityLabel(s string) bool {
	switch strings.ToLower(s) {
	case "critical", "high", "medium", "low", "info":
		return true
	}
	return false
}

func (s *Server) handleScanActivity(w http.ResponseWriter, r *http.Request, id string) {
	tenantID := s.getTenantID(r)
	scan := s.scanStore.GetWithTenant(tenantID, id)
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	scan.mu.RLock()
	events := make([]Event, len(scan.Events))
	copy(events, scan.Events)
	phase := scan.Phase
	status := scan.Status
	findingsCount := len(scan.Findings)
	progress := scan.Progress
	scan.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scanId":        id,
		"status":        status,
		"phase":         phase,
		"progress":      progress,
		"findingsCount": findingsCount,
		"events":        events,
		"activityLog":   events,
	})
}

func (s *Server) handlePortalRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Organization string `json:"organization"`
		Email        string `json:"email"`
		Name         string `json:"name"`
		Plan         string `json:"plan"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Organization == "" {
		http.Error(w, "organization and email required", http.StatusBadRequest)
		return
	}
	if req.Plan == "" {
		req.Plan = "starter"
	}

	tenantID := uuid.New()

	audit.LogStructured("portal", "tenant.register", "tenant", tenantID, "created",
		audit.WithDetail("organization", req.Organization),
		audit.WithDetail("plan", req.Plan),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "registered",
		"tenantId":     tenantID,
		"organization": req.Organization,
		"plan":         req.Plan,
		"message":      "Welcome to ARES! Your tenant has been provisioned.",
	})
}

func (s *Server) handlePortalPlan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"plans": []map[string]interface{}{
			{
				"id":          "starter",
				"name":        "Starter",
				"description": "For small teams getting started with security testing",
				"monthlyScans": 50,
				"concurrentScans": 2,
				"users":          5,
				"features":        []string{"Web Scanning", "API Scanning", "Email Reports"},
			},
			{
				"id":          "professional",
				"name":        "Professional",
				"description": "For growing security teams",
				"monthlyScans": 200,
				"concurrentScans": 5,
				"users":          20,
				"features":        []string{"Everything in Starter", "SIEM Integration", "Compliance Reports", "Priority Support"},
			},
			{
				"id":          "enterprise",
				"name":        "Enterprise",
				"description": "For large organizations with advanced requirements",
				"monthlyScans": 1000,
				"concurrentScans": 20,
				"users":          100,
				"features":        []string{"Everything in Professional", "MSSP/Reseller Mode", "SSO/SAML", "Custom Integrations", "SLA Guarantee"},
			},
			{
				"id":          "mssp",
				"name":        "MSSP/Reseller",
				"description": "For managed service providers and resellers",
				"monthlyScans": 5000,
				"concurrentScans": 50,
				"users":          500,
				"features":        []string{"Everything in Enterprise", "Multi-Tenant Management", "White-Label Reports", "Usage Billing API", "Partner Portal"},
			},
		},
	})
}

func (s *Server) handlePortalBilling(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantID string `json:"tenantId"`
		Plan     string `json:"plan"`
	}
	if r.Method == http.MethodPost {
		if !requireJSONContentType(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_ = req.TenantID // tenant management is a proprietary feature
	}

	tenantID := s.getTenantID(r)
	if req.TenantID != "" {
		tenantID = req.TenantID
	}

	usage := s.usageTracker.Snapshot(tenantID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tenantId":     tenantID,
		"plan":         req.Plan,
		"monthlyUsage": usage,
		"billingCycle": "monthly",
	})
}

func (s *Server) runScan(target string) string {
	scanID := uuid.New()
	scan := &ScanSession{
		ID:        scanID,
		Target:    target,
		StartTime: time.Now(),
		Status:    "running",
		Phase:     "initializing",
		Progress:  0,
		Findings:  make([]Finding, 0),
		Events:    make([]Event, 0),
	}
	s.scanStore.Add(scan)
	if fn := s.getRunScanFn(); fn != nil {
		s.UpdateScanProgress(scanID, "running", "starting", 0)
		go fn(scanID, target, nil)
	}
	return scanID
}
