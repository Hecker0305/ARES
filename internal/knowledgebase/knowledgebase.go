package knowledgebase

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ares/engine/internal/logger"
)

// KBEntry represents a single entry in the local knowledge base.
type KBEntry struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Category    string    `json:"category"`   // cve, ctf, technique, template, payload
	Source      string    `json:"source"`      // e.g., "nvd", "exploit-db", "huggingface"
	Tags        []string  `json:"tags,omitempty"`
	Content     string    `json:"content"`
	Reference   string    `json:"reference,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Score       float64   `json:"score,omitempty"` // FTS5 relevance score
}

// KnowledgeBase provides local, queryable storage for security knowledge.
// Uses SQLite FTS5 for full-text search across CVEs, CTF writeups, 
// exploit techniques, nuclei templates, and red team tactics.
type KnowledgeBase struct {
	mu   sync.RWMutex
	db   *sql.DB
	path string
}

// SearchResult holds a knowledge base search result with relevance score.
type SearchResult struct {
	Entry     KBEntry
	Relevance float64
}

// New opens or creates a knowledge base database at the given path.
func New(path string) (*KnowledgeBase, error) {
	if path == "" {
		path = "ares_knowledge.db"
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open knowledge base: %w", err)
	}

	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA cache_size=-8000", // 8MB cache
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("kb pragma: %w", err)
		}
	}

	kb := &KnowledgeBase{
		db:   db,
		path: path,
	}

	if err := kb.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("kb migrate: %w", err)
	}

	logger.Info("Knowledge base initialized", logger.Fields{"path": path})
	return kb, nil
}

func (kb *KnowledgeBase) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS kb_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT DEFAULT '',
		category TEXT NOT NULL,
		source TEXT DEFAULT '',
		tags TEXT DEFAULT '', -- JSON array
		content TEXT NOT NULL,
		reference TEXT DEFAULT '',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- FTS5 virtual table for full-text search
	CREATE VIRTUAL TABLE IF NOT EXISTS kb_fts USING fts5(
		title,
		description,
		category,
		tags,
		content,
		content='kb_entries',
		content_rowid='id',
		tokenize='porter unicode61'
	);

	-- Triggers to keep FTS index in sync
	CREATE TRIGGER IF NOT EXISTS kb_ai AFTER INSERT ON kb_entries BEGIN
		INSERT INTO kb_fts(rowid, title, description, category, tags, content)
		VALUES (new.id, new.title, new.description, new.category, new.tags, new.content);
	END;

	CREATE TRIGGER IF NOT EXISTS kb_ad AFTER DELETE ON kb_entries BEGIN
		INSERT INTO kb_fts(kb_fts, rowid, title, description, category, tags, content)
		VALUES ('delete', old.id, old.title, old.description, old.category, old.tags, old.content);
	END;

	CREATE TRIGGER IF NOT EXISTS kb_au AFTER UPDATE ON kb_entries BEGIN
		INSERT INTO kb_fts(kb_fts, rowid, title, description, category, tags, content)
		VALUES ('delete', old.id, old.title, old.description, old.category, old.tags, old.content);
		INSERT INTO kb_fts(rowid, title, description, category, tags, content)
		VALUES (new.id, new.title, new.description, new.category, new.tags, new.content);
	END;

	CREATE INDEX IF NOT EXISTS idx_kb_category ON kb_entries(category);
	CREATE INDEX IF NOT EXISTS idx_kb_source ON kb_entries(source);
	`
	_, err := kb.db.Exec(schema)
	return err
}

// Insert adds a new entry to the knowledge base.
func (kb *KnowledgeBase) Insert(entry KBEntry) (int64, error) {
	kb.mu.Lock()
	defer kb.mu.Unlock()

	tagsJSON, _ := json.Marshal(entry.Tags)

	result, err := kb.db.Exec(`
		INSERT INTO kb_entries (title, description, category, source, tags, content, reference)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, entry.Title, entry.Description, entry.Category, entry.Source,
		string(tagsJSON), entry.Content, entry.Reference)
	if err != nil {
		return 0, fmt.Errorf("kb insert: %w", err)
	}

	return result.LastInsertId()
}

// InsertBatch inserts multiple entries in a transaction.
func (kb *KnowledgeBase) InsertBatch(entries []KBEntry) (int, error) {
	kb.mu.Lock()
	defer kb.mu.Unlock()

	tx, err := kb.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("kb batch begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO kb_entries (title, description, category, source, tags, content, reference)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("kb batch prepare: %w", err)
	}
	defer stmt.Close()

	count := 0
	for _, entry := range entries {
		tagsJSON, _ := json.Marshal(entry.Tags)
		if _, err := stmt.Exec(entry.Title, entry.Description, entry.Category,
			entry.Source, string(tagsJSON), entry.Content, entry.Reference); err != nil {
			logger.Warn("KB batch insert skipped", logger.Fields{"title": entry.Title, "error": err.Error()})
			continue
		}
		count++
	}

	if err := tx.Commit(); err != nil {
		return count, fmt.Errorf("kb batch commit: %w", err)
	}

	return count, nil
}

// Search queries the knowledge base using FTS5 full-text search.
// Returns entries ranked by relevance score.
func (kb *KnowledgeBase) Search(ctx context.Context, query string, limit int) ([]SearchResult, error) {
	if limit <= 0 {
		limit = 10
	}

	kb.mu.RLock()
	defer kb.mu.RUnlock()

	// Sanitize query for FTS5 (escape special characters)
	query = sanitizeFTS5(query)
	if query == "" {
		return nil, nil
	}

	rows, err := kb.db.QueryContext(ctx, `
		SELECT e.id, e.title, e.description, e.category, e.source, e.tags, e.content, e.reference, e.created_at,
			   rank
		FROM kb_fts f
		JOIN kb_entries e ON f.rowid = e.id
		WHERE kb_fts MATCH ?
		ORDER BY rank
		LIMIT ?
	`, query, limit)
	if err != nil {
		return nil, fmt.Errorf("kb search: %w", err)
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var entry KBEntry
		var tagsJSON string
		var score float64
		var createdAt string

		if err := rows.Scan(&entry.ID, &entry.Title, &entry.Description,
			&entry.Category, &entry.Source, &tagsJSON, &entry.Content,
			&entry.Reference, &createdAt, &score); err != nil {
			continue
		}

		json.Unmarshal([]byte(tagsJSON), &entry.Tags)
		entry.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		entry.Score = score

		results = append(results, SearchResult{
			Entry:     entry,
			Relevance: score,
		})
	}

	return results, nil
}

// SearchByCategory searches within a specific category.
func (kb *KnowledgeBase) SearchByCategory(ctx context.Context, query, category string, limit int) ([]SearchResult, error) {
	if limit <= 0 {
		limit = 10
	}

	kb.mu.RLock()
	defer kb.mu.RUnlock()

	query = sanitizeFTS5(query)
	if query == "" {
		return nil, nil
	}

	rows, err := kb.db.QueryContext(ctx, `
		SELECT e.id, e.title, e.description, e.category, e.source, e.tags, e.content, e.reference, e.created_at,
			   rank
		FROM kb_fts f
		JOIN kb_entries e ON f.rowid = e.id
		WHERE kb_fts MATCH ? AND e.category = ?
		ORDER BY rank
		LIMIT ?
	`, query, category, limit)
	if err != nil {
		return nil, fmt.Errorf("kb search category: %w", err)
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var entry KBEntry
		var tagsJSON string
		var score float64
		var createdAt string

		if err := rows.Scan(&entry.ID, &entry.Title, &entry.Description,
			&entry.Category, &entry.Source, &tagsJSON, &entry.Content,
			&entry.Reference, &createdAt, &score); err != nil {
			continue
		}

		json.Unmarshal([]byte(tagsJSON), &entry.Tags)
		entry.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		entry.Score = score

		results = append(results, SearchResult{
			Entry:     entry,
			Relevance: score,
		})
	}

	return results, nil
}

// CountByCategory returns the number of entries per category.
func (kb *KnowledgeBase) CountByCategory() (map[string]int, error) {
	kb.mu.RLock()
	defer kb.mu.RUnlock()

	rows, err := kb.db.Query(`SELECT category, COUNT(*) FROM kb_entries GROUP BY category`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var cat string
		var count int
		if err := rows.Scan(&cat, &count); err == nil {
			counts[cat] = count
		}
	}

	return counts, nil
}

// Stats returns summary statistics about the knowledge base.
func (kb *KnowledgeBase) Stats() map[string]interface{} {
	kb.mu.RLock()
	defer kb.mu.RUnlock()

	var totalEntries int
	kb.db.QueryRow("SELECT COUNT(*) FROM kb_entries").Scan(&totalEntries)

	categories, _ := kb.CountByCategory()

	return map[string]interface{}{
		"total_entries": totalEntries,
		"categories":    categories,
		"path":          kb.path,
	}
}

// Close closes the database connection.
func (kb *KnowledgeBase) Close() error {
	return kb.db.Close()
}

// sanitizeFTS5 escapes special FTS5 characters and builds a valid query.
func sanitizeFTS5(query string) string {
	// FTS5 special characters: ^ * " ( ) : + -
	// Escape them by wrapping in quotes, or remove them
	replacer := strings.NewReplacer(
		`"`, `""`, // Double quotes for escaping
		"\n", " ",
		"\r", " ",
		"\t", " ",
	)
	query = replacer.Replace(query)

	// If the query has special chars, wrap in double quotes
	if strings.ContainsAny(query, `^*():+-`) {
		parts := strings.Fields(query)
		for i, p := range parts {
			if strings.ContainsAny(p, `^*():+-`) {
				parts[i] = `"` + p + `"`
			}
		}
		query = strings.Join(parts, " ")
	}

	// Truncate very long queries
	if len(query) > 500 {
		query = query[:500]
	}

	return strings.TrimSpace(query)
}
