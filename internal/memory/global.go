package memory

import "sync"

// GlobalMemory is the shared in-memory store for all scan artifacts.
type GlobalMemory struct {
	mu        sync.RWMutex
	nodes     map[string]interface{}
	sessions  map[string]interface{}
	Strategic *PersistentStrategicMemory
}

// NewGlobalMemory initialises a GlobalMemory instance.
func NewGlobalMemory() *GlobalMemory {
	return &GlobalMemory{
		nodes:     make(map[string]interface{}),
		sessions:  make(map[string]interface{}),
		Strategic: NewPersistentStrategicMemory(),
	}
}

// StoreNode saves any node-like object by ID.
func (m *GlobalMemory) StoreNode(v interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	type ider interface{ GetID() string }
	if id, ok := v.(ider); ok {
		m.nodes[id.GetID()] = v
	}
}

// RegisterActiveSession tracks an active C2 session.
func (m *GlobalMemory) RegisterActiveSession(id string, data map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = data
}
