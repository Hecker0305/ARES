package graph

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type PersistBackend struct {
	mu       sync.RWMutex
	filePath string
	baseDir  string
}

func NewPersist(path string) (*PersistBackend, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	// Reject paths with traversal sequences
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("path traversal not allowed")
	}
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}
	return &PersistBackend{
		filePath: absPath,
		baseDir:  dir,
	}, nil
}

func (p *PersistBackend) validatePath() error {
	absPath, err := filepath.Abs(p.filePath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	if !strings.HasPrefix(absPath, p.baseDir) {
		return fmt.Errorf("path traversal detected: %s", absPath)
	}
	return nil
}

func (p *PersistBackend) Save(g *AttackGraph) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.validatePath(); err != nil {
		return err
	}

	data, err := g.ToJSON()
	if err != nil {
		return err
	}

	tmpPath := p.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, p.filePath)
}

type graphSnapshot struct {
	Nodes map[string]*Node   `json:"nodes"`
	Edges map[string][]*Edge `json:"edges"`
}

func (p *PersistBackend) Load() (*AttackGraph, error) {
	if err := p.validatePath(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(p.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return New(), nil
		}
		return nil, err
	}

	var snap graphSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return New(), nil
	}

	g := New()
	g.mu.Lock()
	for id, node := range snap.Nodes {
		g.nodes[id] = node
	}
	for src, edges := range snap.Edges {
		g.edges[src] = edges
	}
	g.mu.Unlock()

	return g, nil
}
