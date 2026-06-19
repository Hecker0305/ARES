package c2

import "context"

type Manager struct{}

type Client interface {
	Execute(ctx context.Context, cmd string) (string, error)
}

// C2Client is the C2 client interface used by the agent loop for post-exploitation.
// In the open-source build, this is an alias for Client with no-op behavior.
type C2Client interface {
	Client
	GetID() string
}

type noopC2Client struct{}

func (n *noopC2Client) Execute(ctx context.Context, cmd string) (string, error) {
	return "[Enterprise Feature] C2 client not available in open-source build", nil
}

func (n *noopC2Client) GetID() string {
	return ""
}

type Session struct {
	ID string
}

func InitC2FromConfig(cfg interface{}) (*Manager, error) {
	return &Manager{}, nil
}

func MustInitC2FromConfig(cfg interface{}) *Manager {
	return &Manager{}
}

func (m *Manager) GetClient(name string) (C2Client, bool) {
	return &noopC2Client{}, false
}

func (m *Manager) IsConnected() bool {
	return false
}

func (m *Manager) AttemptC2Handoff(ctx context.Context, target string, priority int) *Session {
	return nil
}
