package empire

import (
	"encoding/json"
	"net/http"
)

func (e *EmpireEngine) ExecuteTask(agentName, module, command string) (string, error) {
	body := map[string]string{
		"module":  module,
		"command": command,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return e.doRequest(http.MethodPost, "/api/agents/"+agentName+"/task", jsonBody)
}

func (e *EmpireEngine) GetTaskResults(agentName, taskID string) (string, error) {
	return e.doRequest(http.MethodGet, "/api/agents/"+agentName+"/tasks/"+taskID, nil)
}

func (e *EmpireEngine) ExecuteShellCommand(agentName, cmd string) (string, error) {
	return e.ExecuteTask(agentName, "shell", cmd)
}

func (e *EmpireEngine) ExecutePowerShell(agentName, cmd string) (string, error) {
	return e.ExecuteTask(agentName, "powershell", cmd)
}

func (e *EmpireEngine) ExecuteMimikatz(agentName, mimikatzCmd string) (string, error) {
	return e.ExecuteTask(agentName, "mimikatz", mimikatzCmd)
}

func (e *EmpireEngine) ExecutePortScan(agentName, target string) (string, error) {
	return e.ExecuteTask(agentName, "portscan", target)
}

func (e *EmpireEngine) ListModules() (string, error) {
	return e.doRequest(http.MethodGet, "/api/modules", nil)
}
