package huntmemory

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ares/engine/internal/logger"
)

// SQLiteMemory provides persistent, per-target session memory using SQLite.
// It stores endpoints, parameters, payloads, WAF fingerprints, and tech stack
// so that scans can learn across sessions.
type SQLiteMemory struct {
	mu   sync.RWMutex
	db   *sql.DB
	path string
}

// TargetProfile stores accumulated knowledge about a target
type TargetProfile struct {
	Target      string            `json:"target"`
	Endpoints   []string          `json:"endpoints,omitempty"`
	Params      []string          `json:"params,omitempty"`
	TechStack   map[string]string `json:"tech_stack,omitempty"`
	WAFFingerprint string         `json:"waf_fingerprint,omitempty"`
	LastScanned time.Time         `json:"last_scanned"`
	ScanCount   int               `json:"scan_count"`
}

// PayloadResult records whether a payload succeeded or failed against a target
type PayloadResult struct {
	Target    string    `json:"target"`
	Payload   string    `json:"payload"`
	VulnType  string    `json:"vuln_type"`
	Success   bool      `json:"success"`
	Timestamp time.Time `json:"timestamp"`
}

// NewSQLiteMemory opens or creates a SQLite database at the given path
func NewSQLiteMemory(path string) (*SQLiteMemory, error) {
	if path == "" {
		path = "ares_memory.db"
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Pragmas for performance and safety
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite pragma: %w", err)
		}
	}

	sm := &SQLiteMemory{
		db:   db,
		path: path,
	}

	if err := sm.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite migrate: %w", err)
	}

	logger.Info("SQLite hunt memory initialized", logger.Fields{"path": path})
	return sm, nil
}

func (sm *SQLiteMemory) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS targets (
		target TEXT PRIMARY KEY,
		tech_stack TEXT DEFAULT '',
		waf_fingerprint TEXT DEFAULT '',
		last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		scan_count INTEGER DEFAULT 1,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS endpoints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		endpoint TEXT NOT NULL,
		method TEXT DEFAULT 'GET',
		params TEXT DEFAULT '',
		first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (target) REFERENCES targets(target) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS payloads (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		payload TEXT NOT NULL,
		vuln_type TEXT NOT NULL,
		success INTEGER NOT NULL DEFAULT 0,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (target) REFERENCES targets(target) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_payloads_target ON payloads(target);
	CREATE INDEX IF NOT EXISTS idx_payloads_success ON payloads(success);
	CREATE INDEX IF NOT EXISTS idx_endpoints_target ON endpoints(target);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		target TEXT NOT NULL,
		started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		ended_at TIMESTAMP,
		findings_count INTEGER DEFAULT 0,
		FOREIGN KEY (target) REFERENCES targets(target) ON DELETE CASCADE
	);
	`
	_, err := sm.db.Exec(schema)
	return err
}

// EnsureTarget creates or updates a target record
func (sm *SQLiteMemory) EnsureTarget(target string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, err := sm.db.Exec(`
		INSERT INTO targets (target, scan_count)
		VALUES (?, 1)
		ON CONFLICT(target) DO UPDATE SET
			scan_count = scan_count + 1,
			last_scanned = CURRENT_TIMESTAMP
	`, target)
	return err
}

// RecordEndpoint records an endpoint discovered for a target
func (sm *SQLiteMemory) RecordEndpoint(target, endpoint, method, params string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Upsert: if endpoint exists, update last_seen
	_, err := sm.db.Exec(`
		INSERT INTO endpoints (target, endpoint, method, params)
		VALUES (?, ?, ?, ?)
		ON CONFLICT DO NOTHING
	`, target, endpoint, method, params)
	return err
}

// RecordPayload records whether a payload succeeded or failed
func (sm *SQLiteMemory) RecordPayload(target, payload, vulnType string, success bool) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	successInt := 0
	if success {
		successInt = 1
	}
	_, err := sm.db.Exec(`
		INSERT INTO payloads (target, payload, vuln_type, success)
		VALUES (?, ?, ?, ?)
	`, target, payload, vulnType, successInt)
	return err
}

// SetTechStack stores the detected technology stack for a target
func (sm *SQLiteMemory) SetTechStack(target, techStack string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, err := sm.db.Exec(`
		UPDATE targets SET tech_stack = ? WHERE target = ?
	`, techStack, target)
	return err
}

// SetWAFFingerprint stores the WAF fingerprint for a target
func (sm *SQLiteMemory) SetWAFFingerprint(target, waf string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, err := sm.db.Exec(`
		UPDATE targets SET waf_fingerprint = ? WHERE target = ?
	`, waf, target)
	return err
}

// GetTargetProfile retrieves all stored knowledge about a target
func (sm *SQLiteMemory) GetTargetProfile(ctx context.Context, target string) (*TargetProfile, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	profile := &TargetProfile{
		Target:    target,
		TechStack: make(map[string]string),
	}

	// Get target metadata
	row := sm.db.QueryRowContext(ctx, `
		SELECT tech_stack, waf_fingerprint, last_scanned, scan_count
		FROM targets WHERE target = ?
	`, target)
	var techStack, waf string
	var lastScanned time.Time
	if err := row.Scan(&techStack, &waf, &lastScanned, &profile.ScanCount); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	profile.TechStack["raw"] = techStack
	profile.WAFFingerprint = waf
	profile.LastScanned = lastScanned

	// Get endpoints
	endpointRows, err := sm.db.QueryContext(ctx, `
		SELECT endpoint, method, params FROM endpoints WHERE target = ?
	`, target)
	if err != nil {
		return nil, err
	}
	defer endpointRows.Close()
	for endpointRows.Next() {
		var endpoint, method, params string
		if err := endpointRows.Scan(&endpoint, &method, &params); err != nil {
			continue
		}
		profile.Endpoints = append(profile.Endpoints, endpoint)
		if params != "" {
			profile.Params = append(profile.Params, params)
		}
	}

	return profile, nil
}

// GetSuccessfulPayloads returns payloads that worked for a target and vulnerability type
func (sm *SQLiteMemory) GetSuccessfulPayloads(ctx context.Context, target, vulnType string) ([]string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	rows, err := sm.db.QueryContext(ctx, `
		SELECT payload FROM payloads
		WHERE target = ? AND vuln_type = ? AND success = 1
		ORDER BY timestamp DESC
	`, target, vulnType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var payloads []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			continue
		}
		payloads = append(payloads, p)
	}
	return payloads, nil
}

// GetFailedPayloads returns payloads that failed for a target and vulnerability type
func (sm *SQLiteMemory) GetFailedPayloads(ctx context.Context, target, vulnType string) ([]string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	rows, err := sm.db.QueryContext(ctx, `
		SELECT payload FROM payloads
		WHERE target = ? AND vuln_type = ? AND success = 0
		ORDER BY timestamp DESC
	`, target, vulnType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var payloads []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			continue
		}
		payloads = append(payloads, p)
	}
	return payloads, nil
}

// StartSession records the beginning of a scan session
func (sm *SQLiteMemory) StartSession(id, target string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, err := sm.db.Exec(`
		INSERT INTO sessions (id, target) VALUES (?, ?)
	`, id, target)
	return err
}

// EndSession records the end of a scan session
func (sm *SQLiteMemory) EndSession(id string, findingsCount int) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, err := sm.db.Exec(`
		UPDATE sessions SET ended_at = CURRENT_TIMESTAMP, findings_count = ?
		WHERE id = ?
	`, findingsCount, id)
	return err
}

// Close closes the database connection
func (sm *SQLiteMemory) Close() error {
	return sm.db.Close()
}

// Compile-time interface check
var _ interface {
	EnsureTarget(string) error
	RecordEndpoint(string, string, string, string) error
	RecordPayload(string, string, string, bool) error
	SetTechStack(string, string) error
	SetWAFFingerprint(string, string) error
	StartSession(string, string) error
	EndSession(string, int) error
	Close() error
} = (*SQLiteMemory)(nil)
