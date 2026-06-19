package agentdeploy

import (
	"github.com/ares/engine/internal/uuid"
	"fmt"
	"sync"
	"time"
)

type AgentStatus string

const (
	AgentOffline  AgentStatus = "offline"
	AgentOnline   AgentStatus = "online"
	AgentScanning AgentStatus = "scanning"
	AgentError    AgentStatus = "error"
)

type AgentType string

const (
	AgentLightweight AgentType = "lightweight"
	AgentFull        AgentType = "full"
	AgentScanner     AgentType = "scanner"
)

type DeployedAgent struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Type           AgentType         `json:"type"`
	Status         AgentStatus       `json:"status"`
	Version        string            `json:"version"`
	Hostname       string            `json:"hostname"`
	IPAddress      string            `json:"ip_address"`
	OS             string            `json:"os"`
	NetworkSegment string            `json:"network_segment"`
	Capabilities   []string          `json:"capabilities,omitempty"`
	LastHeartbeat  time.Time         `json:"last_heartbeat"`
	DeployedAt     time.Time         `json:"deployed_at"`
	Tags           map[string]string `json:"tags,omitempty"`
}

type ScanTask struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	Target      string    `json:"target"`
	ScanType    string    `json:"scan_type"`
	Status      string    `json:"status"`
	Result      string    `json:"result,omitempty"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type AgentManager struct {
	mu            sync.RWMutex
	agents        map[string]*DeployedAgent
	tasks         []ScanTask
	checkInterval time.Duration
	stopCh        chan struct{}
}

func New(checkInterval time.Duration) *AgentManager {
	return &AgentManager{
		agents:        make(map[string]*DeployedAgent),
		checkInterval: checkInterval,
		stopCh:        make(chan struct{}),
	}
}

func (am *AgentManager) Start() {
	go am.heartbeatLoop()
}

func (am *AgentManager) Stop() {
	close(am.stopCh)
}

func (am *AgentManager) heartbeatLoop() {
	ticker := time.NewTicker(am.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			am.mu.Lock()
			now := time.Now()
			for _, agent := range am.agents {
				if now.Sub(agent.LastHeartbeat) > 5*am.checkInterval {
					agent.Status = AgentOffline
				}
			}
			am.mu.Unlock()
		case <-am.stopCh:
			return
		}
	}
}

func (am *AgentManager) Register(agent DeployedAgent) string {
	am.mu.Lock()
	defer am.mu.Unlock()

	if agent.ID == "" {
		agent.ID = uuid.New()
	}
	agent.Status = AgentOnline
	agent.LastHeartbeat = time.Now()
	agent.DeployedAt = time.Now()
	if agent.Version == "" {
		agent.Version = "2.0.0"
	}
	if agent.Capabilities == nil {
		agent.Capabilities = []string{"port_scan", "service_detect", "vuln_scan"}
	}
	am.agents[agent.ID] = &agent
	return agent.ID
}

func (am *AgentManager) Heartbeat(id string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	agent, ok := am.agents[id]
	if !ok {
		return false
	}
	agent.LastHeartbeat = time.Now()
	agent.Status = AgentOnline
	return true
}

func (am *AgentManager) GetAgent(id string) *DeployedAgent {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.agents[id]
}

func (am *AgentManager) ListAgents() []*DeployedAgent {
	am.mu.RLock()
	defer am.mu.RUnlock()
	result := make([]*DeployedAgent, 0, len(am.agents))
	for _, agent := range am.agents {
		result = append(result, agent)
	}
	return result
}

func (am *AgentManager) ListAgentsBySegment(segment string) []*DeployedAgent {
	am.mu.RLock()
	defer am.mu.RUnlock()
	var result []*DeployedAgent
	for _, agent := range am.agents {
		if agent.NetworkSegment == segment {
			result = append(result, agent)
		}
	}
	return result
}

func (am *AgentManager) RemoveAgent(id string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	_, ok := am.agents[id]
	if !ok {
		return false
	}
	delete(am.agents, id)
	return true
}

func (am *AgentManager) AssignScan(agentID, target, scanType string) (string, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	agent, ok := am.agents[agentID]
	if !ok {
		return "", fmt.Errorf("agent %s not found", agentID)
	}
	if agent.Status != AgentOnline {
		return "", fmt.Errorf("agent %s is not online (status: %s)", agentID, agent.Status)
	}

	task := ScanTask{
		ID:       uuid.New(),
		AgentID:  agentID,
		Target:   target,
		ScanType: scanType,
		Status:   "assigned",
	}
	am.tasks = append(am.tasks, task)
	agent.Status = AgentScanning
	return task.ID, nil
}

func (am *AgentManager) CompleteScan(taskID, result string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	for i := range am.tasks {
		if am.tasks[i].ID == taskID {
			am.tasks[i].Status = "completed"
			am.tasks[i].Result = result
			am.tasks[i].CompletedAt = time.Now()
			if agent, ok := am.agents[am.tasks[i].AgentID]; ok {
				agent.Status = AgentOnline
			}
			return true
		}
	}
	return false
}

func (am *AgentManager) GetTasks(agentID string) []ScanTask {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var result []ScanTask
	for _, t := range am.tasks {
		if agentID == "" || t.AgentID == agentID {
			result = append(result, t)
		}
	}
	return result
}

func (am *AgentManager) GetStats() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()

	statusCount := make(map[AgentStatus]int)
	typeCount := make(map[AgentType]int)
	segments := make(map[string]int)

	for _, agent := range am.agents {
		statusCount[agent.Status]++
		typeCount[agent.Type]++
		if agent.NetworkSegment != "" {
			segments[agent.NetworkSegment]++
		}
	}

	return map[string]interface{}{
		"total_agents":    len(am.agents),
		"online_agents":   statusCount[AgentOnline],
		"offline_agents":  statusCount[AgentOffline],
		"scanning_agents": statusCount[AgentScanning],
		"by_type":         typeCount,
		"by_segment":      segments,
		"total_tasks":     len(am.tasks),
	}
}
