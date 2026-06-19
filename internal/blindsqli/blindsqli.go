package blindsqli

import (
	"database/sql"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
)

type State struct {
	TargetID     string
	Payload      string
	DBMS         string
	Iteration    int
	MaxIteration int
	Table        string
	Column       string
	Value        string
	Complete     bool
	LastUpdated  time.Time
}

type BinaryQuestion struct {
	Position int
	Low      int
	High     int
	Question string
	Answer   bool
}

type TimingSample struct {
	Timestamp time.Time
	Duration  time.Duration
}

type TimingDetector struct {
	mu        sync.Mutex
	samples   map[string][]TimingSample
	baselines map[string]time.Duration
}

func NewTimingDetector() *TimingDetector {
	return &TimingDetector{
		samples:   make(map[string][]TimingSample),
		baselines: make(map[string]time.Duration),
	}
}

func (td *TimingDetector) RecordSample(targetID string, duration time.Duration) {
	td.mu.Lock()
	defer td.mu.Unlock()
	td.samples[targetID] = append(td.samples[targetID], TimingSample{
		Timestamp: time.Now(),
		Duration:  duration,
	})
}

func (td *TimingDetector) CalculateBaseline(targetID string) time.Duration {
	td.mu.Lock()
	defer td.mu.Unlock()
	samples, ok := td.samples[targetID]
	if !ok || len(samples) == 0 {
		return 0
	}
	if len(samples) < 3 {
		var total time.Duration
		for _, s := range samples {
			total += s.Duration
		}
		return total / time.Duration(len(samples))
	}
	durations := make([]float64, len(samples))
	for i, s := range samples {
		durations[i] = float64(s.Duration)
	}
	mean := meanDuration(durations)
	median := medianDuration(durations)
	stddev := stddevDuration(durations, mean)
	threshold := median + 2*stddev
	td.baselines[targetID] = time.Duration(threshold)
	return time.Duration(median)
}

func (td *TimingDetector) IsSignificantDelay(targetID string, observed time.Duration) bool {
	td.mu.Lock()
	defer td.mu.Unlock()
	baseline, ok := td.baselines[targetID]
	if !ok {
		samples := td.samples[targetID]
		if len(samples) < 3 {
			return false
		}
		durations := make([]float64, len(samples))
		for i, s := range samples {
			durations[i] = float64(s.Duration)
		}
		mean := meanDuration(durations)
		stddev := stddevDuration(durations, mean)
		baseline = time.Duration(mean + 2*stddev)
	}
	return observed > baseline
}

func (td *TimingDetector) GetNetworkVariance(targetID string) float64 {
	td.mu.Lock()
	defer td.mu.Unlock()
	samples := td.samples[targetID]
	if len(samples) < 2 {
		return 0
	}
	durations := make([]float64, len(samples))
	for i, s := range samples {
		durations[i] = float64(s.Duration)
	}
	mean := meanDuration(durations)
	return stddevDuration(durations, mean)
}

func meanDuration(durations []float64) float64 {
	var sum float64
	for _, d := range durations {
		sum += d
	}
	return sum / float64(len(durations))
}

func medianDuration(durations []float64) float64 {
	sorted := make([]float64, len(durations))
	copy(sorted, durations)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

func stddevDuration(durations []float64, mean float64) float64 {
	var sum float64
	for _, d := range durations {
		diff := d - mean
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(durations)))
}

type Manager struct {
	db          *sql.DB
	detector    *TimingDetector
	rateLimiter chan struct{}
}

func NewManager(db *sql.DB) *Manager {
	m := &Manager{
		db:          db,
		detector:    NewTimingDetector(),
		rateLimiter: make(chan struct{}, 10),
	}
	m.initSchema()
	return m
}

func (m *Manager) initSchema() {
	if m.db == nil {
		return
	}
	schema := `
	CREATE TABLE IF NOT EXISTS blindsqli_states (
		target_id VARCHAR(256) PRIMARY KEY,
		payload TEXT,
		dbms VARCHAR(64),
		iteration INTEGER DEFAULT 0,
		max_iteration INTEGER DEFAULT 32,
		bs_table VARCHAR(128),
		bs_column VARCHAR(128),
		bs_value TEXT,
		complete BOOLEAN DEFAULT FALSE,
		last_updated TIMESTAMP DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS blindsqli_binary_log (
		id SERIAL PRIMARY KEY,
		target_id VARCHAR(256),
		position INTEGER,
		char_code INTEGER,
		answer BOOLEAN,
		timestamp TIMESTAMP DEFAULT NOW(),
		FOREIGN KEY (target_id) REFERENCES blindsqli_states(target_id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS blindsqli_timing_samples (
		id SERIAL PRIMARY KEY,
		target_id VARCHAR(256),
		duration_ms INTEGER,
		is_significant BOOLEAN DEFAULT FALSE,
		timestamp TIMESTAMP DEFAULT NOW(),
		FOREIGN KEY (target_id) REFERENCES blindsqli_states(target_id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_blindsqli_target ON blindsqli_states(target_id);
	CREATE INDEX IF NOT EXISTS idx_binary_target ON blindsqli_binary_log(target_id);
	CREATE INDEX IF NOT EXISTS idx_timing_target ON blindsqli_timing_samples(target_id);
	`
	_, err := m.db.Exec(schema)
	if err != nil {
		return
	}
}

func (m *Manager) NewState(targetID, payload, dbms string) error {
	if m.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	if targetID == "" {
		return fmt.Errorf("target ID is required")
	}
	_, err := m.db.Exec(`
		INSERT INTO blindsqli_states (target_id, payload, dbms, iteration, max_iteration, complete, last_updated)
		VALUES ($1, $2, $3, 0, 32, false, NOW())
		ON CONFLICT (target_id) DO UPDATE SET
			payload=$2, dbms=$3, iteration=0, complete=false, last_updated=NOW()
	`, targetID, payload, dbms)
	return err
}

func (m *Manager) GetState(targetID string) (*State, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}
	var s State
	var payload, dbms, table, column, value sql.NullString
	err := m.db.QueryRow(`
		SELECT target_id, payload, dbms, iteration, max_iteration, bs_table, bs_column, bs_value, complete, last_updated
		FROM blindsqli_states WHERE target_id=$1
	`, targetID).Scan(
		&s.TargetID, &payload, &dbms, &s.Iteration, &s.MaxIteration,
		&table, &column, &value, &s.Complete, &s.LastUpdated,
	)
	if err != nil {
		return nil, err
	}
	if payload.Valid {
		s.Payload = payload.String
	}
	if dbms.Valid {
		s.DBMS = dbms.String
	}
	if table.Valid {
		s.Table = table.String
	}
	if column.Valid {
		s.Column = column.String
	}
	if value.Valid {
		s.Value = value.String
	}
	return &s, nil
}

func (m *Manager) AskBinaryQuestion(targetID string, position, charCode int) string {
	return fmt.Sprintf("Is ASCII character at position %d greater than %d? (respond YES if true, NO if false)", position, charCode)
}

func (m *Manager) RecordAnswer(targetID string, position, charCode int, answer bool) error {
	if m.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	_, err := m.db.Exec(`
		INSERT INTO blindsqli_binary_log (target_id, position, char_code, answer)
		VALUES ($1, $2, $3, $4)
	`, targetID, position, charCode, answer)
	return err
}

func (m *Manager) ReconstructValue(targetID string) (string, error) {
	if m.db == nil {
		return "", fmt.Errorf("database connection is nil")
	}
	rows, err := m.db.Query(`
		SELECT position, char_code FROM blindsqli_binary_log
		WHERE target_id=$1 ORDER BY position, char_code
	`, targetID)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var chars []int
	for rows.Next() {
		var pos, code int
		if err := rows.Scan(&pos, &code); err != nil {
			return "", err
		}
		for len(chars) <= pos {
			chars = append(chars, 0)
		}
		chars[pos] = code
	}

	var sb strings.Builder
	for _, c := range chars {
		if c > 0 {
			sb.WriteRune(rune(c))
		}
	}
	return sb.String(), nil
}

func (m *Manager) UpdateIteration(targetID string, iteration int) error {
	if m.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	_, err := m.db.Exec(`UPDATE blindsqli_states SET iteration=$1, last_updated=NOW() WHERE target_id=$2`, iteration, targetID)
	return err
}

func (m *Manager) SetComplete(targetID, value string) error {
	if m.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	_, err := m.db.Exec(`UPDATE blindsqli_states SET complete=true, bs_value=$1, last_updated=NOW() WHERE target_id=$2`, value, targetID)
	return err
}

func (m *Manager) GetPsuccess(targetID, vulnType string) float64 {
	if m.db == nil {
		return 0.5
	}
	var p float64
	err := m.db.QueryRow(`
		SELECT p_success FROM strategic_memory WHERE target=$1 AND vuln_type=$2
	`, targetID, vulnType).Scan(&p)
	if err != nil {
		return 0.5
	}
	return p
}

func (m *Manager) SerializeForLLM(targetID string) (string, error) {
	if m.db == nil {
		return "", fmt.Errorf("database connection is nil")
	}
	state, err := m.GetState(targetID)
	if err != nil {
		return "", err
	}

	rows, err := m.db.Query(`
		SELECT position, char_code, answer FROM blindsqli_binary_log
		WHERE target_id=$1 ORDER BY position, char_code LIMIT 100
	`, targetID)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var confirmed []string
	posCounts := make(map[int]int)
	for rows.Next() {
		var pos, code int
		var ans bool
		if err := rows.Scan(&pos, &code, &ans); err != nil {
			logger.Error(fmt.Sprintf("[BlindSQLi] failed to scan binary log row: %v", err))
			continue
		}
		posCounts[pos]++
		if ans {
			confirmed = append(confirmed, fmt.Sprintf("pos%d=chr(%d)", pos, code))
		}
	}

	currentPos := 0
	if len(posCounts) > 0 {
		maxPos := 0
		for p := range posCounts {
			if p > maxPos {
				maxPos = p
			}
		}
		for i := 0; i <= maxPos; i++ {
			if posCounts[i] > 0 {
				currentPos = i + 1
			}
		}
	}

	question := m.AskBinaryQuestion(targetID, currentPos, 77)

	return fmt.Sprintf(`[Blind SQLi State]
Target: %s
Iteration: %d/%d
Table: %s | Column: %s
Confirmed chars: %v
Next question (binary): %s
Respond: YES if true, NO if false, EXTRACT if done`,
		state.TargetID, state.Iteration, state.MaxIteration,
		state.Table, state.Column, confirmed, question), nil
}

func (m *Manager) RecordTimingSample(targetID string, duration time.Duration) {
	if m.detector == nil {
		return
	}
	m.detector.RecordSample(targetID, duration)
}

func (m *Manager) EvaluateTimingSignificance(targetID string, observed time.Duration) bool {
	if m.detector == nil {
		return false
	}
	return m.detector.IsSignificantDelay(targetID, observed)
}

func (m *Manager) GetTimingBaseline(targetID string) time.Duration {
	if m.detector == nil {
		return 0
	}
	return m.detector.CalculateBaseline(targetID)
}

func (m *Manager) GetNetworkVariance(targetID string) float64 {
	if m.detector == nil {
		return 0
	}
	return m.detector.GetNetworkVariance(targetID)
}
