package migration

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ares/engine/internal/logger"
)

type Migration struct {
	ID   int
	Name string
	Up   func() error
	Down func() error
}

type Runner struct {
	migrations []Migration
	statePath  string
}

func NewRunner(statePath string) *Runner {
	return &Runner{
		statePath: statePath,
	}
}

func (r *Runner) Add(m Migration) {
	r.migrations = append(r.migrations, m)
}

func (r *Runner) Run() error {
	if len(r.migrations) == 0 {
		return nil
	}

	sort.Slice(r.migrations, func(i, j int) bool {
		return r.migrations[i].ID < r.migrations[j].ID
	})

	applied, err := r.loadApplied()
	if err != nil {
		applied = make(map[int]bool)
	}

	for _, m := range r.migrations {
		if applied[m.ID] {
			continue
		}

		logger.Info(fmt.Sprintf("[Migration] Applying %03d_%s", m.ID, m.Name))
		if err := m.Up(); err != nil {
			return fmt.Errorf("migration %03d_%s failed: %w", m.ID, m.Name, err)
		}

		applied[m.ID] = true
		if err := r.saveApplied(applied); err != nil {
			logger.Warn(fmt.Sprintf("[Migration] Failed to save applied state: %v", err))
		}

		logger.Info(fmt.Sprintf("[Migration] Applied %03d_%s", m.ID, m.Name))
	}

	return nil
}

func (r *Runner) Rollback(targetID int) error {
	applied, err := r.loadApplied()
	if err != nil {
		return fmt.Errorf("failed to load applied migrations: %w", err)
	}

	var toRollback []Migration
	for i := len(r.migrations) - 1; i >= 0; i-- {
		m := r.migrations[i]
		if applied[m.ID] && m.ID > targetID {
			toRollback = append(toRollback, m)
		}
	}

	sort.Slice(toRollback, func(i, j int) bool {
		return toRollback[i].ID > toRollback[j].ID
	})

	for _, m := range toRollback {
		logger.Info(fmt.Sprintf("[Migration] Rolling back %03d_%s", m.ID, m.Name))
		if err := m.Down(); err != nil {
			return fmt.Errorf("rollback %03d_%s failed: %w", m.ID, m.Name, err)
		}
		delete(applied, m.ID)
		r.saveApplied(applied)
		logger.Info(fmt.Sprintf("[Migration] Rolled back %03d_%s", m.ID, m.Name))
	}

	return nil
}

func (r *Runner) loadApplied() (map[int]bool, error) {
	data, err := os.ReadFile(r.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[int]bool), nil
		}
		return nil, err
	}

	applied := make(map[int]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		id, err := strconv.Atoi(line)
		if err == nil {
			applied[id] = true
		}
	}
	return applied, nil
}

func (r *Runner) saveApplied(applied map[int]bool) error {
	os.MkdirAll(filepath.Dir(r.statePath), 0700)

	var ids []int
	for id := range applied {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	var sb strings.Builder
	for _, id := range ids {
		sb.WriteString(fmt.Sprintf("%d\n", id))
	}

	tmpPath := r.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(sb.String()), 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, r.statePath)
}

func (r *Runner) Status() []map[string]interface{} {
	applied, _ := r.loadApplied()
	var status []map[string]interface{}

	for _, m := range r.migrations {
		status = append(status, map[string]interface{}{
			"id":      m.ID,
			"name":    m.Name,
			"applied": applied[m.ID],
		})
	}
	return status
}
