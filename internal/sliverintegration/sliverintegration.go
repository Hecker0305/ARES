package sliverintegration

type ServerConfig struct {
	Host   string
	Port   int
	CACert string
	LHost  string
	LPort  int
}

type Manager struct{}

func NewManager(cfg ServerConfig) *Manager {
	return &Manager{}
}

func (m *Manager) StartServer() error {
	return nil
}

func (m *Manager) StopServer() {}
