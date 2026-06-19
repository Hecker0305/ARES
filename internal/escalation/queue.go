package escalation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/selfheal"
	"github.com/ares/engine/internal/uuid"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

var saveSem = make(chan struct{}, 3)

func getAppBaseURL() string {
	if url := os.Getenv("ARES_APP_URL"); url != "" {
		return url
	}
	return "http://localhost:8080"
}

type AuditEntry struct {
	Action      string    `json:"action"`
	PerformedBy string    `json:"performed_by"`
	Note        string    `json:"note"`
	Timestamp   time.Time `json:"timestamp"`
}

type SMTPConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

type NearFinding struct {
	ID           string       `json:"id"`
	Title        string       `json:"title"`
	Endpoint     string       `json:"endpoint"`
	VulnType     string       `json:"vuln_type"`
	Confidence   float64      `json:"confidence"`
	Evidence     string       `json:"evidence"`
	Severity     string       `json:"severity"`
	Phase        string       `json:"phase"`
	CreatedAt    time.Time    `json:"created_at"`
	Status       string       `json:"status"`
	OperatorNote string       `json:"operator_note"`
	SLADeadline  time.Time    `json:"sla_deadline"`
	History      []AuditEntry `json:"history"`
}

type Queue struct {
	mu              sync.RWMutex
	items           map[string]*NearFinding
	watchers        []chan *NearFinding
	persistencePath string
	requiredRole    string
}

type queueData struct {
	Items map[string]*NearFinding `json:"items"`
}

var severityOrder = []string{"low", "medium", "high", "critical"}

func slaDurationFor(severity string) time.Duration {
	switch severity {
	case "critical":
		return 30 * time.Minute
	case "high":
		return 2 * time.Hour
	case "medium":
		return 8 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func nextSeverity(current string) string {
	for i, s := range severityOrder {
		if s == current && i < len(severityOrder)-1 {
			return severityOrder[i+1]
		}
	}
	return current
}

func NewQueue() *Queue {
	return &Queue{
		items:        make(map[string]*NearFinding),
		watchers:     make([]chan *NearFinding, 0),
		requiredRole: "operator",
	}
}

func NewQueueWithPersistence(path string) *Queue {
	q := &Queue{
		items:           make(map[string]*NearFinding),
		watchers:        make([]chan *NearFinding, 0),
		persistencePath: path,
		requiredRole:    "operator",
	}
	if err := q.load(path); err != nil {
		logger.Info(fmt.Sprintf("[Escalation] No saved queue state to load: %v", err))
	}
	return q
}

func (q *Queue) SetRequiredRole(role string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.requiredRole = role
}

func (q *Queue) checkPermissionLocked(operatorRole string) error {
	required := q.requiredRole

	roleHierarchy := map[string]int{
		"viewer":   0,
		"operator": 1,
		"admin":    2,
	}

	opLevel, opOk := roleHierarchy[operatorRole]
	reqLevel, reqOk := roleHierarchy[required]
	if !opOk || !reqOk {
		return fmt.Errorf("invalid role: operator=%s required=%s", operatorRole, required)
	}
	if opLevel < reqLevel {
		return fmt.Errorf("insufficient permissions: role %q requires %q", operatorRole, required)
	}
	return nil
}

func (q *Queue) checkPermission(operatorRole string) error {
	q.mu.RLock()
	required := q.requiredRole
	q.mu.RUnlock()

	roleHierarchy := map[string]int{
		"viewer":   0,
		"operator": 1,
		"admin":    2,
	}

	opLevel, opOk := roleHierarchy[operatorRole]
	reqLevel, reqOk := roleHierarchy[required]
	if !opOk || !reqOk {
		return fmt.Errorf("invalid role: operator=%s required=%s", operatorRole, required)
	}
	if opLevel < reqLevel {
		return fmt.Errorf("insufficient permissions: role %q requires %q", operatorRole, required)
	}
	return nil
}

func (q *Queue) save() error {
	if q.persistencePath == "" {
		return nil
	}

	q.mu.RLock()
	itemsCopy := make(map[string]*NearFinding, len(q.items))
	for k, v := range q.items {
		itemsCopy[k] = v
	}
	q.mu.RUnlock()

	data := queueData{Items: itemsCopy}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal queue: %w", err)
	}

	dir := filepath.Dir(q.persistencePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create persistence dir: %w", err)
	}
	if err := os.WriteFile(q.persistencePath, b, 0600); err != nil {
		return fmt.Errorf("write queue file: %w", err)
	}
	return nil
}

func (q *Queue) load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var data queueData
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	if data.Items == nil {
		data.Items = make(map[string]*NearFinding)
	}
	q.items = data.Items
	return nil
}

func (q *Queue) Add(nf *NearFinding) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if nf.ID == "" {
		nf.ID = uuid.New()
	}
	nf.CreatedAt = time.Now()
	nf.Status = "pending"
	nf.SLADeadline = time.Now().Add(slaDurationFor(nf.Severity))

	nf.History = append(nf.History, AuditEntry{
		Action:      "created",
		PerformedBy: "system",
		Note:        fmt.Sprintf("Finding created with severity %s", nf.Severity),
		Timestamp:   time.Now(),
	})
	q.items[nf.ID] = nf

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- q.save() }()
		select {
		case err := <-done:
			if err != nil {
				logger.Warn(fmt.Sprintf("[Escalation] Failed to save queue: %v", err))
			}
		case <-ctx.Done():
			logger.Warn("[Escalation] Queue save timed out")
		}
	}()

	watchers := make([]chan *NearFinding, len(q.watchers))
	copy(watchers, q.watchers)

	for _, ch := range watchers {
		select {
		case ch <- nf:
		default:
		}
	}
}

func (q *Queue) confirmLocked(id, note, operatorRole string) error {
	if err := q.checkPermissionLocked(operatorRole); err != nil {
		return err
	}
	if nf, ok := q.items[id]; ok {
		nf.Status = "confirmed"
		nf.OperatorNote = note
		nf.History = append(nf.History, AuditEntry{
			Action:      "confirmed",
			PerformedBy: operatorRole,
			Note:        note,
			Timestamp:   time.Now(),
		})

		healEngine := selfheal.New()
		plan := healEngine.BuildRemediationPlan([]string{nf.VulnType})
		if plan != nil && len(plan.Patches) > 0 {
			logger.Info(fmt.Sprintf("[Escalation] Auto-remediation plan generated: P%d priority for %s", plan.Priority, nf.VulnType))
		}
		return nil
	}
	return fmt.Errorf("finding %s not found", id)
}

func (q *Queue) Confirm(id, note, operatorRole string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	err := q.confirmLocked(id, note, operatorRole)
	if err == nil {
		go func() {
			saveSem <- struct{}{}
			defer func() { <-saveSem }()
			if err := q.save(); err != nil {
				logger.Warn(fmt.Sprintf("[Escalation] Failed to save queue: %v", err))
			}
		}()
	}
	return err
}

func (q *Queue) dismissLocked(id, reason, operatorRole string) error {
	if err := q.checkPermissionLocked(operatorRole); err != nil {
		return err
	}
	if nf, ok := q.items[id]; ok {
		nf.Status = "dismissed"
		nf.OperatorNote = reason
		nf.History = append(nf.History, AuditEntry{
			Action:      "dismissed",
			PerformedBy: operatorRole,
			Note:        reason,
			Timestamp:   time.Now(),
		})
		return nil
	}
	return fmt.Errorf("finding %s not found", id)
}

func (q *Queue) Dismiss(id, reason, operatorRole string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	err := q.dismissLocked(id, reason, operatorRole)
	if err == nil {
		go func() {
			saveSem <- struct{}{}
			defer func() { <-saveSem }()
			if err := q.save(); err != nil {
				logger.Warn(fmt.Sprintf("[Escalation] Failed to save queue: %v", err))
			}
		}()
	}
	return err
}

func (q *Queue) Get(id string) *NearFinding {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.items[id]
}

func (q *Queue) List() []*NearFinding {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var out []*NearFinding
	for _, nf := range q.items {
		out = append(out, nf)
	}
	return out
}

func (q *Queue) Pending() []*NearFinding {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var out []*NearFinding
	for _, nf := range q.items {
		if nf.Status == "pending" {
			out = append(out, nf)
		}
	}
	return out
}

func (q *Queue) Subscribe() chan *NearFinding {
	ch := make(chan *NearFinding, 5)
	q.mu.Lock()
	q.watchers = append(q.watchers, ch)
	q.mu.Unlock()
	return ch
}

func (q *Queue) Unsubscribe(ch chan *NearFinding) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, w := range q.watchers {
		if w == ch {
			close(ch)
			q.watchers = append(q.watchers[:i], q.watchers[i+1:]...)
			return
		}
	}
}

func (q *Queue) Cleanup(olderThan time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	for id, nf := range q.items {
		if nf.CreatedAt.Before(cutoff) && (nf.Status == "confirmed" || nf.Status == "dismissed") {
			delete(q.items, id)
		}
	}

	go func() {
		if err := q.save(); err != nil {
			logger.Warn(fmt.Sprintf("[Escalation] Failed to save queue: %v", err))
		}
	}()
}

func (q *Queue) NotifySlack(webhookURL string, nf *NearFinding) error {
	if webhookURL == "" {
		return fmt.Errorf("webhook URL is empty")
	}

	color := "#36a64f"
	switch nf.Severity {
	case "critical":
		color = "#FF0000"
	case "high":
		color = "#FFA500"
	case "medium":
		color = "#FFFF00"
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf(":warning: *Near-Finding Alert:* %s", nf.Title),
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": nf.Title,
				"fields": []map[string]interface{}{
					{"title": "ID", "value": nf.ID, "short": true},
					{"title": "Severity", "value": nf.Severity, "short": true},
					{"title": "Confidence", "value": fmt.Sprintf("%.1f%%", nf.Confidence*100), "short": true},
					{"title": "Endpoint", "value": nf.Endpoint, "short": true},
					{"title": "Vuln Type", "value": nf.VulnType, "short": true},
					{"title": "Phase", "value": nf.Phase, "short": true},
					{"title": "Status", "value": nf.Status, "short": true},
					{"title": "Created", "value": nf.CreatedAt.Format(time.RFC3339), "short": true},
					{"title": "SLA Deadline", "value": nf.SLADeadline.Format(time.RFC3339), "short": true},
					{"title": "Evidence", "value": nf.Evidence, "short": false},
				},
				"actions": []map[string]interface{}{
					{
						"type":  "button",
						"text":  "Confirm",
						"url":   fmt.Sprintf("%s/escalation/confirm/%s", getAppBaseURL(), nf.ID),
						"style": "primary",
					},
					{
						"type":  "button",
						"text":  "Dismiss",
						"url":   fmt.Sprintf("%s/escalation/dismiss/%s", getAppBaseURL(), nf.ID),
						"style": "danger",
					},
				},
				"ts": time.Now().Unix(),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("slack post request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}
	return nil
}

func (q *Queue) NotifyEmail(cfg SMTPConfig, nf *NearFinding) error {
	if len(cfg.To) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	subject := fmt.Sprintf("[%s] Near-Finding Alert: %s", nf.Severity, nf.Title)
	body := fmt.Sprintf(`Near-Finding Alert

Title:      %s
ID:         %s
Severity:   %s
Confidence: %.1f%%
Endpoint:   %s
Vuln Type:  %s
Phase:      %s
Status:     %s
Created:    %s
SLA By:     %s

Evidence:
%s

Actions:
  Confirm: %s/escalation/confirm/%s
  Dismiss: %s/escalation/dismiss/%s
`,
		nf.Title,
		nf.ID,
		nf.Severity,
		nf.Confidence*100,
		nf.Endpoint,
		nf.VulnType,
		nf.Phase,
		nf.Status,
		nf.CreatedAt.Format(time.RFC3339),
		nf.SLADeadline.Format(time.RFC3339),
		nf.Evidence,
		getAppBaseURL(), nf.ID,
		getAppBaseURL(), nf.ID,
	)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\n%s",
		cfg.From, cfg.To[0], subject, body)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	tlsCfg := &tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("TLS dial SMTP: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("SMTP client creation: %w", err)
	}
	defer client.Close()

	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP auth: %w", err)
	}

	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("SMTP mail from: %w", err)
	}

	for _, to := range cfg.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP rcpt %s: %w", to, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP data: %w", err)
	}

	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("SMTP write: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP close: %w", err)
	}

	return client.Quit()
}

func (q *Queue) SLAExceeded() []*NearFinding {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var out []*NearFinding
	now := time.Now()
	for _, nf := range q.items {
		if nf.Status == "pending" && now.After(nf.SLADeadline) {
			out = append(out, nf)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SLADeadline.Before(out[j].SLADeadline)
	})
	return out
}

func (q *Queue) AutoEscalate(nf *NearFinding) *NearFinding {
	q.mu.Lock()
	defer q.mu.Unlock()

	item, ok := q.items[nf.ID]
	if !ok {
		return nil
	}
	if item.Status != "pending" {
		return item
	}

	sla := slaDurationFor(item.Severity)
	doubleDeadline := item.SLADeadline.Add(sla)
	if !time.Now().After(doubleDeadline) {
		return item
	}

	newSeverity := nextSeverity(item.Severity)
	if newSeverity == item.Severity {
		return item
	}

	oldSeverity := item.Severity
	item.History = append(item.History, AuditEntry{
		Action:      "auto-escalated",
		PerformedBy: "system",
		Note:        fmt.Sprintf("Auto-escalated from %s to %s (SLA exceeded by 2x)", oldSeverity, newSeverity),
		Timestamp:   time.Now(),
	})
	item.Severity = newSeverity
	item.SLADeadline = time.Now().Add(slaDurationFor(newSeverity))

	go func() {
		if err := q.save(); err != nil {
			logger.Warn(fmt.Sprintf("[Escalation] Failed to save queue: %v", err))
		}
	}()

	logger.Info(fmt.Sprintf("[Escalation] Auto-escalated finding %s from %s to %s", item.ID, oldSeverity, newSeverity))
	return item
}

func (q *Queue) AuditTrail(id string) []AuditEntry {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if nf, ok := q.items[id]; ok {
		return nf.History
	}
	return nil
}

func (q *Queue) ConfirmBatch(ids []string, note, operatorRole string) []error {
	q.mu.Lock()
	defer q.mu.Unlock()

	errs := make([]error, 0, len(ids))
	for _, id := range ids {
		if err := q.confirmLocked(id, note, operatorRole); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) < len(ids) {
		go func() {
			saveSem <- struct{}{}
			defer func() { <-saveSem }()
			if err := q.save(); err != nil {
				logger.Warn(fmt.Sprintf("[Escalation] Failed to save queue: %v", err))
			}
		}()
	}
	return errs
}

func (q *Queue) DismissBatch(ids []string, reason, operatorRole string) []error {
	q.mu.Lock()
	defer q.mu.Unlock()

	errs := make([]error, 0, len(ids))
	for _, id := range ids {
		if err := q.dismissLocked(id, reason, operatorRole); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) < len(ids) {
		go func() {
			saveSem <- struct{}{}
			defer func() { <-saveSem }()
			if err := q.save(); err != nil {
				logger.Warn(fmt.Sprintf("[Escalation] Failed to save queue: %v", err))
			}
		}()
	}
	return errs
}

func IsRunningAsRoot() bool {
	if runtime.GOOS == "windows" {
		u, err := user.Current()
		if err != nil {
			return false
		}
		return u.Username == "Administrator" || u.Uid == "S-1-5-18"
	}
	return os.Geteuid() == 0
}

func DropPrivileges() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("refusing to run with elevated privileges; drop to non-root user before execution")
	}
	return nil
}

func ShouldEscalate(confidence float64, evidence string) bool {
	return confidence >= 0.7 && confidence < 0.95 && evidence != ""
}

func BuildEscalation(target, endpoint, vulnType string, confidence float64, evidence, phase string) *NearFinding {
	severity := "low"
	if confidence >= 0.85 {
		severity = "high"
	} else if confidence >= 0.8 {
		severity = "medium"
	}

	return &NearFinding{
		Title:      fmt.Sprintf("Partial: %s on %s (%s)", vulnType, endpoint, target),
		Endpoint:   endpoint,
		VulnType:   vulnType,
		Confidence: confidence,
		Evidence:   evidence,
		Severity:   severity,
		Phase:      phase,
	}
}
