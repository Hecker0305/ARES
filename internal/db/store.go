package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/scrypt"

	"database/sql"

	"github.com/ares/engine/internal/logger"
)

type PersistedSession struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type PersistedFinding struct {
	ID          string            `json:"id"`
	ScanID      string            `json:"scan_id"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Target      string            `json:"target"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Evidence    map[string]string `json:"evidence"`
	MitreTags   []string          `json:"mitre_tags"`
	CVSS        float64           `json:"cvss"`
	Confirmed   bool              `json:"confirmed"`
	Timestamp   time.Time         `json:"timestamp"`
}

type PersistedScan struct {
	ID        string             `json:"id"`
	Target    string             `json:"target"`
	StartTime time.Time          `json:"start_time"`
	Status    string             `json:"status"`
	Findings  []PersistedFinding `json:"findings"`
	Phase     string             `json:"phase"`
	Progress  float64            `json:"progress"`
	TenantID  string             `json:"tenant_id,omitempty"`
}

type WebhookEntry struct {
	ID      string `json:"id"`
	URL     string `json:"url"`
	Type    string `json:"type"`
	Events  string `json:"events"`
	Enabled bool   `json:"enabled"`
}

type SQLStore struct {
	db         *sql.DB
	dbType     string
	encryptKey []byte
	aead       cipher.AEAD
}

func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	return NewSQLStoreWithType(db, "sqlite")
}

func NewSQLStoreWithType(db *sql.DB, dbType string) (*SQLStore, error) {
	key := deriveEncryptionKey()
	if key == nil {
		return nil, fmt.Errorf("encryption key not available; set ARES_ENCRYPTION_KEY or configure key file")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	s := &SQLStore{
		db:         db,
		dbType:     dbType,
		encryptKey: key,
		aead:       aead,
	}

	s.cleanup()
	return s, nil
}

func deriveEncryptionKey() []byte {
	envKey := os.Getenv("ARES_ENCRYPTION_KEY")
	if envKey != "" {
		decoded, err := hex.DecodeString(envKey)
		if err == nil && len(decoded) == 32 {
			return decoded
		}
		salt := []byte("ares-db-store-v1")
		key, err := scrypt.Key([]byte(envKey), salt, 32768, 8, 1, 32)
		if err == nil {
			return key
		}
		hash := sha256.Sum256([]byte(envKey))
		return hash[:]
	}

	keyDir, err := os.UserHomeDir()
	if err != nil {
		keyDir = os.TempDir()
	}
	keyFile := filepath.Join(keyDir, ".ares", "encryption.key")
	if data, err := os.ReadFile(keyFile); err == nil && len(data) == 32 {
		return data
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		logger.Error("[SQLStore] CRITICAL: Failed to generate encryption key")
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(keyFile), 0700); err != nil {
		logger.Warn(fmt.Sprintf("[SQLStore] Failed to create key directory: %v", err))
	} else if err := os.WriteFile(keyFile, key, 0600); err != nil {
		logger.Warn(fmt.Sprintf("[SQLStore] Failed to persist encryption key: %v", err))
	}
	return key
}

func (s *SQLStore) cleanup() {
	if s.dbType == "postgres" {
		s.db.Exec("DELETE FROM scan_results WHERE start_time < NOW() - INTERVAL '7 days'")
		s.db.Exec("DELETE FROM findings WHERE timestamp < NOW() - INTERVAL '7 days'")
		s.db.Exec("DELETE FROM sessions WHERE expires_at < NOW()")
	} else {
		s.db.Exec("DELETE FROM scan_results WHERE datetime(start_time) < datetime('now', '-7 days')")
		s.db.Exec("DELETE FROM findings WHERE datetime(timestamp) < datetime('now', '-7 days')")
		s.db.Exec("DELETE FROM sessions WHERE datetime(expires_at) < datetime('now')")
	}
}

func (s *SQLStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *SQLStore) SaveScan(scan *PersistedScan) error {
	if s.dbType == "postgres" {
		_, err := s.db.Exec(`
			INSERT INTO scan_results (id, target, start_time, status, phase, progress, tenant_id, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
			ON CONFLICT (id) DO UPDATE SET target=$2, start_time=$3, status=$4, phase=$5, progress=$6, tenant_id=$7, updated_at=NOW()
		`, scan.ID, scan.Target, scan.StartTime.Format(time.RFC3339), scan.Status, scan.Phase, scan.Progress, scan.TenantID)
		return err
	}
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO scan_results (id, target, start_time, status, phase, progress, tenant_id, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
	`, scan.ID, scan.Target, scan.StartTime.Format(time.RFC3339), scan.Status, scan.Phase, scan.Progress, scan.TenantID)
	return err
}

func (s *SQLStore) GetScan(id string) (*PersistedScan, error) {
	scan := &PersistedScan{}
	var startTimeStr string

	var query string
	if s.dbType == "postgres" {
		query = `SELECT id, target, start_time, status, phase, progress, COALESCE(tenant_id, '') FROM scan_results WHERE id = $1`
	} else {
		query = `SELECT id, target, start_time, status, phase, progress, COALESCE(tenant_id, '') FROM scan_results WHERE id = ?`
	}

	err := s.db.QueryRow(query, id).Scan(&scan.ID, &scan.Target, &startTimeStr, &scan.Status, &scan.Phase, &scan.Progress, &scan.TenantID)
	if err != nil {
		return nil, err
	}

	if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
		scan.StartTime = t
	}

	findings, err := s.ListFindings(id)
	if err == nil {
		for _, f := range findings {
			scan.Findings = append(scan.Findings, *f)
		}
	}

	return scan, nil
}

func (s *SQLStore) ListScans(tenantID string) ([]*PersistedScan, error) {
	var rows *sql.Rows
	var err error

	if s.dbType == "postgres" {
		if tenantID == "" {
			rows, err = s.db.Query(`
				SELECT id, target, start_time, status, phase, progress, COALESCE(tenant_id, '')
				FROM scan_results ORDER BY start_time DESC
			`)
		} else {
			rows, err = s.db.Query(`
				SELECT id, target, start_time, status, phase, progress, COALESCE(tenant_id, '')
				FROM scan_results WHERE tenant_id = $1 ORDER BY start_time DESC
			`, tenantID)
		}
	} else {
		if tenantID == "" {
			rows, err = s.db.Query(`
				SELECT id, target, start_time, status, phase, progress, COALESCE(tenant_id, '')
				FROM scan_results ORDER BY start_time DESC
			`)
		} else {
			rows, err = s.db.Query(`
				SELECT id, target, start_time, status, phase, progress, COALESCE(tenant_id, '')
				FROM scan_results WHERE tenant_id = ? ORDER BY start_time DESC
			`, tenantID)
		}
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*PersistedScan
	for rows.Next() {
		scan := &PersistedScan{}
		var startTimeStr string
		if err := rows.Scan(&scan.ID, &scan.Target, &startTimeStr, &scan.Status, &scan.Phase, &scan.Progress, &scan.TenantID); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			scan.StartTime = t
		}
		scans = append(scans, scan)
	}

	return scans, rows.Err()
}

func (s *SQLStore) DeleteScan(id string) error {
	if s.dbType == "postgres" {
		_, err := s.db.Exec("DELETE FROM scan_results WHERE id = $1", id)
		return err
	}
	_, err := s.db.Exec("DELETE FROM scan_results WHERE id = ?", id)
	return err
}

func (s *SQLStore) SaveFinding(f *PersistedFinding) error {
	evidenceJSON, _ := json.Marshal(f.Evidence)
	mitreJSON, _ := json.Marshal(f.MitreTags)

	if s.dbType == "postgres" {
		_, err := s.db.Exec(`
			INSERT INTO findings (id, scan_id, type, severity, target, title, description, evidence, mitre_tags, cvss, confirmed, timestamp)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO UPDATE SET scan_id=$2, type=$3, severity=$4, target=$5, title=$6, description=$7, evidence=$8, mitre_tags=$9, cvss=$10, confirmed=$11, timestamp=$12
		`, f.ID, f.ScanID, f.Type, f.Severity, f.Target, f.Title, f.Description, string(evidenceJSON), string(mitreJSON), f.CVSS, f.Confirmed, f.Timestamp.Format(time.RFC3339))
		return err
	}
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO findings (id, scan_id, type, severity, target, title, description, evidence, mitre_tags, cvss, confirmed, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, f.ID, f.ScanID, f.Type, f.Severity, f.Target, f.Title, f.Description, string(evidenceJSON), string(mitreJSON), f.CVSS, f.Confirmed, f.Timestamp.Format(time.RFC3339))
	return err
}

func (s *SQLStore) GetFinding(id string) (*PersistedFinding, error) {
	f := &PersistedFinding{}
	var evidenceJSON, mitreJSON, timestampStr string

	var query string
	if s.dbType == "postgres" {
		query = `SELECT id, scan_id, type, severity, target, title, COALESCE(description, ''), COALESCE(evidence, '{}'), COALESCE(mitre_tags, '[]'), cvss, confirmed, timestamp FROM findings WHERE id = $1`
	} else {
		query = `SELECT id, scan_id, type, severity, target, title, COALESCE(description, ''), COALESCE(evidence, '{}'), COALESCE(mitre_tags, '[]'), cvss, confirmed, timestamp FROM findings WHERE id = ?`
	}

	err := s.db.QueryRow(query, id).Scan(&f.ID, &f.ScanID, &f.Type, &f.Severity, &f.Target, &f.Title, &f.Description, &evidenceJSON, &mitreJSON, &f.CVSS, &f.Confirmed, &timestampStr)
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(evidenceJSON), &f.Evidence)
	json.Unmarshal([]byte(mitreJSON), &f.MitreTags)
	if t, err := time.Parse(time.RFC3339, timestampStr); err == nil {
		f.Timestamp = t
	} else {
		logger.Warn(fmt.Sprintf("[SQLStore] Failed to parse timestamp for finding %s: %v", f.ID, err))
	}

	return f, nil
}

func (s *SQLStore) ListFindings(scanID string) ([]*PersistedFinding, error) {
	var rows *sql.Rows
	var err error

	if s.dbType == "postgres" {
		if scanID == "" {
			rows, err = s.db.Query(`
				SELECT id, scan_id, type, severity, target, title, COALESCE(description, ''), COALESCE(evidence, '{}'), COALESCE(mitre_tags, '[]'), cvss, confirmed, timestamp
				FROM findings ORDER BY timestamp DESC
			`)
		} else {
			rows, err = s.db.Query(`
				SELECT id, scan_id, type, severity, target, title, COALESCE(description, ''), COALESCE(evidence, '{}'), COALESCE(mitre_tags, '[]'), cvss, confirmed, timestamp
				FROM findings WHERE scan_id = $1 ORDER BY timestamp DESC
			`, scanID)
		}
	} else {
		if scanID == "" {
			rows, err = s.db.Query(`
				SELECT id, scan_id, type, severity, target, title, COALESCE(description, ''), COALESCE(evidence, '{}'), COALESCE(mitre_tags, '[]'), cvss, confirmed, timestamp
				FROM findings ORDER BY timestamp DESC
			`)
		} else {
			rows, err = s.db.Query(`
				SELECT id, scan_id, type, severity, target, title, COALESCE(description, ''), COALESCE(evidence, '{}'), COALESCE(mitre_tags, '[]'), cvss, confirmed, timestamp
				FROM findings WHERE scan_id = ? ORDER BY timestamp DESC
			`, scanID)
		}
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*PersistedFinding
	for rows.Next() {
		f := &PersistedFinding{}
		var evidenceJSON, mitreJSON, timestampStr string
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Type, &f.Severity, &f.Target, &f.Title, &f.Description, &evidenceJSON, &mitreJSON, &f.CVSS, &f.Confirmed, &timestampStr); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(evidenceJSON), &f.Evidence)
		json.Unmarshal([]byte(mitreJSON), &f.MitreTags)
		if t, err := time.Parse(time.RFC3339, timestampStr); err == nil {
			f.Timestamp = t
		}
		findings = append(findings, f)
	}

	return findings, rows.Err()
}

func (s *SQLStore) SaveSession(session *PersistedSession) error {
	token := session.Token
	if s.aead != nil {
		token = s.encryptValue(session.Token)
	}

	if s.dbType == "postgres" {
		_, err := s.db.Exec(`
			INSERT INTO sessions (token, username, role, expires_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (token) DO UPDATE SET username=$2, role=$3, expires_at=$4
		`, token, session.Username, session.Role, session.ExpiresAt.Format(time.RFC3339))
		return err
	}
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO sessions (token, username, role, expires_at)
		VALUES (?, ?, ?, ?)
	`, token, session.Username, session.Role, session.ExpiresAt.Format(time.RFC3339))
	return err
}

func (s *SQLStore) GetSession(token string) (*PersistedSession, error) {
	lookupToken := token
	if s.aead != nil {
		lookupToken = s.encryptValue(token)
	}

	sess := &PersistedSession{}
	var expiresStr string

	var query string
	if s.dbType == "postgres" {
		query = `SELECT token, username, role, expires_at FROM sessions WHERE token = $1`
	} else {
		query = `SELECT token, username, role, expires_at FROM sessions WHERE token = ?`
	}

	err := s.db.QueryRow(query, lookupToken).Scan(&sess.Token, &sess.Username, &sess.Role, &expiresStr)
	if err != nil {
		return nil, err
	}

	if s.aead != nil {
		sess.Token = s.decryptValue(sess.Token)
	}
	if t, err := time.Parse(time.RFC3339, expiresStr); err == nil {
		sess.ExpiresAt = t
	}

	return sess, nil
}

func (s *SQLStore) DeleteSession(token string) error {
	storedToken := token
	if s.aead != nil {
		storedToken = s.encryptValue(token)
	}

	if s.dbType == "postgres" {
		_, err := s.db.Exec("DELETE FROM sessions WHERE token = $1", storedToken)
		return err
	}
	_, err := s.db.Exec("DELETE FROM sessions WHERE token = ?", storedToken)
	return err
}

func (s *SQLStore) SaveWebhook(entry *WebhookEntry) error {
	url := entry.URL
	if s.aead != nil {
		url = s.encryptValue(entry.URL)
	}

	if s.dbType == "postgres" {
		_, err := s.db.Exec(`
			INSERT INTO webhooks (id, url, type, events, enabled)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) DO UPDATE SET url=$2, type=$3, events=$4, enabled=$5
		`, entry.ID, url, entry.Type, entry.Events, entry.Enabled)
		return err
	}
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO webhooks (id, url, type, events, enabled)
		VALUES (?, ?, ?, ?, ?)
	`, entry.ID, url, entry.Type, entry.Events, entry.Enabled)
	return err
}

func (s *SQLStore) ListWebhooks() ([]*WebhookEntry, error) {
	rows, err := s.db.Query(`
		SELECT id, url, type, COALESCE(events, ''), enabled FROM webhooks ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*WebhookEntry
	for rows.Next() {
		w := &WebhookEntry{}
		if err := rows.Scan(&w.ID, &w.URL, &w.Type, &w.Events, &w.Enabled); err != nil {
			return nil, err
		}
		if s.aead != nil {
			w.URL = s.decryptValue(w.URL)
		}
		webhooks = append(webhooks, w)
	}

	return webhooks, rows.Err()
}

func (s *SQLStore) DeleteWebhook(id string) error {
	if s.dbType == "postgres" {
		_, err := s.db.Exec("DELETE FROM webhooks WHERE id = $1", id)
		return err
	}
	_, err := s.db.Exec("DELETE FROM webhooks WHERE id = ?", id)
	return err
}

func (s *SQLStore) encryptValue(plaintext string) string {
	if s.aead == nil {
		return plaintext
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		logger.Warn("[SQLStore] Failed to generate nonce for encryption")
		return plaintext
	}
	ciphertext := s.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func (s *SQLStore) decryptValue(encoded string) string {
	if s.aead == nil {
		return encoded
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		logger.Warn("[SQLStore] Failed to decode encrypted value")
		return encoded
	}
	nonceSize := s.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		logger.Warn("[SQLStore] Encrypted value too short")
		return encoded
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		logger.Warn("[SQLStore] Failed to decrypt value")
		return encoded
	}
	return string(plaintext)
}

func (s *SQLStore) CountScans(tenantID string) (int, error) {
	var count int
	var err error
	if s.dbType == "postgres" {
		if tenantID == "" {
			err = s.db.QueryRow("SELECT COUNT(*) FROM scan_results").Scan(&count)
		} else {
			err = s.db.QueryRow("SELECT COUNT(*) FROM scan_results WHERE tenant_id = $1", tenantID).Scan(&count)
		}
	} else {
		if tenantID == "" {
			err = s.db.QueryRow("SELECT COUNT(*) FROM scan_results").Scan(&count)
		} else {
			err = s.db.QueryRow("SELECT COUNT(*) FROM scan_results WHERE tenant_id = ?", tenantID).Scan(&count)
		}
	}
	return count, err
}

func (s *SQLStore) UpdateScanProgress(id string, phase string, progress float64) error {
	if s.dbType == "postgres" {
		_, err := s.db.Exec(`
			UPDATE scan_results SET phase = $1, progress = $2, updated_at = NOW() WHERE id = $3
		`, phase, progress, id)
		return err
	}
	_, err := s.db.Exec(`
		UPDATE scan_results SET phase = ?, progress = ?, updated_at = datetime('now') WHERE id = ?
	`, phase, progress, id)
	return err
}

func (s *SQLStore) UpdateScanStatus(id string, status string) error {
	if s.dbType == "postgres" {
		_, err := s.db.Exec(`
			UPDATE scan_results SET status = $1, updated_at = NOW() WHERE id = $2
		`, status, id)
		return err
	}
	_, err := s.db.Exec(`
		UPDATE scan_results SET status = ?, updated_at = datetime('now') WHERE id = ?
	`, status, id)
	return err
}

func (s *SQLStore) GetAuditLogs(limit int) ([]map[string]interface{}, error) {
	var rows *sql.Rows
	var err error

	if s.dbType == "postgres" {
		rows, err = s.db.Query(`
			SELECT id, timestamp, COALESCE(user_id, ''), action, COALESCE(resource_type, ''), COALESCE(resource_id, ''), COALESCE(details, ''), COALESCE(ip_address, '')
			FROM audit_log ORDER BY timestamp DESC LIMIT $1
		`, limit)
	} else {
		rows, err = s.db.Query(`
			SELECT id, timestamp, COALESCE(user_id, ''), action, COALESCE(resource_type, ''), COALESCE(resource_id, ''), COALESCE(details, ''), COALESCE(ip_address, '')
			FROM audit_log ORDER BY timestamp DESC LIMIT ?
		`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id, ts, userID, action, resType, resID, details, ip string
		if err := rows.Scan(&id, &ts, &userID, &action, &resType, &resID, &details, &ip); err != nil {
			return nil, err
		}
		logs = append(logs, map[string]interface{}{
			"id":            id,
			"timestamp":     ts,
			"user_id":       userID,
			"action":        action,
			"resource_type": resType,
			"resource_id":   resID,
			"details":       details,
			"ip_address":    ip,
		})
	}

	return logs, rows.Err()
}

func (s *SQLStore) AddAuditLog(userID, action, resType, resID, details, ip string) error {
	if s.dbType == "postgres" {
		_, err := s.db.Exec(`
			INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, ip_address)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, userID, action, resType, resID, details, ip)
		return err
	}
	_, err := s.db.Exec(`
		INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, ip_address)
		VALUES (?, ?, ?, ?, ?, ?)
	`, userID, action, resType, resID, details, ip)
	return err
}

func (s *SQLStore) MigrateFromJSON(dataDir string) error {
	jsonStorePath := filepath.Join(dataDir, "scans.json")
	if _, err := os.Stat(jsonStorePath); err != nil {
		return nil
	}

	data, err := os.ReadFile(jsonStorePath)
	if err != nil {
		return fmt.Errorf("read scans.json: %w", err)
	}

	var scans map[string]*PersistedScan
	if err := json.Unmarshal(data, &scans); err != nil {
		return fmt.Errorf("parse scans: %w", err)
	}

	for _, scan := range scans {
		if err := s.SaveScan(scan); err != nil {
			return fmt.Errorf("migrate scan %s: %w", scan.ID, err)
		}
		for _, f := range scan.Findings {
			if err := s.SaveFinding(&f); err != nil {
				return fmt.Errorf("migrate finding %s: %w", f.ID, err)
			}
		}
	}

	logger.Info("[SQLStore] Migrated %d scans from JSON store", logger.Fields{"count": len(scans)})
	return nil
}
