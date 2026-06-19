package engine

// siem_extended.go — Elastic + Datadog SIEM connectors + SIEMRouter.
//
// Adds to the existing Splunk + Sentinel connectors in siem.go:
//   ElasticConnector  — Elasticsearch ECS threat field mapping
//   DatadogConnector  — Datadog Events API v1 security signals
//   SIEMRouter        — fan-out to all configured connectors
//   SIEMFromEnv()     — auto-init from env vars

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/secrets"
)

// ════════════════════════════════════════════════════════════════════════
// ElasticConnector — Elasticsearch / Elastic SIEM (ECS format)
// ════════════════════════════════════════════════════════════════════════

type ElasticConnector struct {
	url    string // e.g. "https://cluster.es.io:9200"
	apiKey string // base64(id:key) from Kibana API Key management
	index  string // default "ares-findings"
	client *http.Client
}

func NewElasticConnector(url, apiKey, index string) *ElasticConnector {
	if index == "" {
		index = "ares-findings"
	}
	return &ElasticConnector{
		url:    strings.TrimRight(url, "/"),
		apiKey: apiKey,
		index:  index,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}
}

func (e *ElasticConnector) SendAlert(ctx context.Context, finding map[string]interface{}) error {
	doc := map[string]interface{}{
		"@timestamp": time.Now().UTC().Format(time.RFC3339),
		"event": map[string]interface{}{
			"kind":     "alert",
			"category": []string{"intrusion_detection"},
			"type":     []string{"indicator"},
		},
		"vulnerability": map[string]interface{}{
			"id":          finding["cve"],
			"severity":    finding["severity"],
			"description": finding["description"],
		},
		"host":   map[string]interface{}{"name": finding["target"]},
		"labels": map[string]interface{}{"source": "ares"},
		"ares":   finding,
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("elastic marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", e.url+"/"+e.index+"/_doc", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "ApiKey "+e.apiKey)
	req.Header.Set("Content-Type", "application/json")
	logger.Info(fmt.Sprintf("[SIEM/Elastic] Indexing → %s/%s", e.url, e.index))
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("elastic: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("elastic HTTP %d: %s", resp.StatusCode, body)
	}
	logger.Info(fmt.Sprintf("[SIEM/Elastic] Indexed (HTTP %d)", resp.StatusCode))
	return nil
}

// ════════════════════════════════════════════════════════════════════════
// DatadogConnector — Datadog Events API v1
// ════════════════════════════════════════════════════════════════════════

type DatadogConnector struct {
	apiKey string
	appKey string
	site   string // e.g. "datadoghq.com" or "datadoghq.eu"
	client *http.Client
}

func NewDatadogConnector(apiKey, appKey, site string) *DatadogConnector {
	if site == "" {
		site = "datadoghq.com"
	}
	return &DatadogConnector{apiKey: apiKey, appKey: appKey, site: site,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				TLSHandshakeTimeout: 10 * time.Second,
			},
		}}
}

func (d *DatadogConnector) SendAlert(ctx context.Context, finding map[string]interface{}) error {
	severity := fmt.Sprintf("%v", finding["severity"])
	alertType := "info"
	if severity == "critical" || severity == "high" {
		alertType = "error"
	} else if severity == "medium" {
		alertType = "warning"
	}
	payload := map[string]interface{}{
		"title": fmt.Sprintf("[Ares] %v on %v", finding["vulnerability"], finding["target"]),
		"text": fmt.Sprintf("**Severity**: %s\n**Target**: %v\n**Details**: %v",
			severity, finding["target"], finding["description"]),
		"alert_type":       alertType,
		"source_type_name": "SECURITY",
		"tags":             []string{"source:ares", "severity:" + severity},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("datadog marshal: %w", err)
	}
	url := fmt.Sprintf("https://api.%s/api/v1/events", d.site)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("DD-API-KEY", d.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", d.appKey)
	req.Header.Set("Content-Type", "application/json")
	logger.Info(fmt.Sprintf("[SIEM/Datadog] Sending → %s", url))
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("datadog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("datadog HTTP %d: %s", resp.StatusCode, body)
	}
	logger.Info(fmt.Sprintf("[SIEM/Datadog] Sent (HTTP %d)", resp.StatusCode))
	return nil
}

// ════════════════════════════════════════════════════════════════════════
// SIEMRouter — fan-out + env-based auto-init
// ════════════════════════════════════════════════════════════════════════

// SIEMRouter fans a single alert to all registered connectors.
type SIEMRouter struct {
	connectors []SIEMConnector
}

func (r *SIEMRouter) Add(c SIEMConnector) { r.connectors = append(r.connectors, c) }

func (r *SIEMRouter) SendAlert(ctx context.Context, finding map[string]interface{}) error {
	var errs []string
	for _, c := range r.connectors {
		if err := c.SendAlert(ctx, finding); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("siem: %s", strings.Join(errs, "; "))
	}
	return nil
}

// SIEMFromEnv builds a SIEMRouter auto-configured from environment variables.
//
//	SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN
//	SENTINEL_WORKSPACE_ID, SENTINEL_SHARED_KEY
//	ELASTIC_URL, ELASTIC_API_KEY, ELASTIC_INDEX
//	DATADOG_API_KEY, DATADOG_APP_KEY, DATADOG_SITE
func SIEMFromEnv() *SIEMRouter {
	r := &SIEMRouter{}
	if url := secrets.Get("SPLUNK_HEC_URL"); url != "" {
		r.Add(NewSplunkConnector(url, secrets.Get("SPLUNK_HEC_TOKEN")))
		logger.Info("[SIEM] Splunk HEC enabled")
	}
	if ws := secrets.Get("SENTINEL_WORKSPACE_ID"); ws != "" {
		r.Add(NewSentinelConnector(ws, secrets.Get("SENTINEL_SHARED_KEY")))
		logger.Info("[SIEM] Azure Sentinel enabled")
	}
	if url := secrets.Get("ELASTIC_URL"); url != "" {
		r.Add(NewElasticConnector(url, secrets.Get("ELASTIC_API_KEY"), secrets.Get("ELASTIC_INDEX")))
		logger.Info("[SIEM] Elastic enabled")
	}
	if k := secrets.Get("DATADOG_API_KEY"); k != "" {
		r.Add(NewDatadogConnector(k, secrets.Get("DATADOG_APP_KEY"), secrets.Get("DATADOG_SITE")))
		logger.Info("[SIEM] Datadog enabled")
	}
	if len(r.connectors) == 0 {
		logger.Info("[SIEM] No SIEM connectors (set SPLUNK/SENTINEL/ELASTIC/DATADOG env vars)")
	}
	return r
}
