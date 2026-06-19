package empire

import (
	"encoding/json"
	"net/http"
)

func (e *EmpireEngine) ListAgents() (string, error) {
	return e.doRequest(http.MethodGet, "/api/agents", nil)
}

func (e *EmpireEngine) InteractAgent(agentName string) (string, error) {
	return e.doRequest(http.MethodGet, "/api/agents/"+agentName, nil)
}

func (e *EmpireEngine) RenameAgent(agentName, newName string) (string, error) {
	body := map[string]string{
		"new_name": newName,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/agents/"+agentName+"/rename", jsonBody)
}

func (e *EmpireEngine) KillAgent(agentName string) (string, error) {
	return e.doRequest(http.MethodPost, "/api/agents/"+agentName+"/kill", nil)
}

func (e *EmpireEngine) RemoveAgent(agentName string) (string, error) {
	return e.doRequest(http.MethodDelete, "/api/agents/"+agentName, nil)
}
