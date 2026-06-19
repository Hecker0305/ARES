package mythic

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ares/engine/internal/logger"
)

func (e *MythicEngine) GetCallbacks() ([]MythicCallback, error) {
	data, err := e.apiCall("GET", "/api/v1.4/callbacks", nil)
	if err != nil {
		return nil, fmt.Errorf("get callbacks: %w", err)
	}

	var resp struct {
		Status    string          `json:"status"`
		Callbacks []MythicCallback `json:"callbacks"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse callbacks: %w", err)
	}

	e.mu.Lock()
	for i := range resp.Callbacks {
		e.callbacks[resp.Callbacks[i].ID] = &resp.Callbacks[i]
	}
	e.mu.Unlock()

	return resp.Callbacks, nil
}

func (e *MythicEngine) GetCallbackByID(id int) (*MythicCallback, error) {
	data, err := e.apiCall("GET", fmt.Sprintf("/api/v1.4/callbacks/%d", id), nil)
	if err != nil {
		return nil, fmt.Errorf("get callback %d: %w", id, err)
	}

	var resp struct {
		Status   string        `json:"status"`
		Callback MythicCallback `json:"callback"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse callback: %w", err)
	}

	e.mu.Lock()
	e.callbacks[resp.Callback.ID] = &resp.Callback
	e.mu.Unlock()

	return &resp.Callback, nil
}

func (e *MythicEngine) GetActiveCallbacks() ([]MythicCallback, error) {
	callbacks, err := e.GetCallbacks()
	if err != nil {
		return nil, err
	}

	var active []MythicCallback
	for _, cb := range callbacks {
		if cb.Active {
			active = append(active, cb)
		}
	}
	return active, nil
}

func (e *MythicEngine) SubmitTask(callbackID int, command string, params map[string]interface{}) (*MythicTask, error) {
	payload := map[string]interface{}{
		"callback_id": callbackID,
		"command":     command,
		"params":      params,
	}
	body, _ := json.Marshal(payload)

	data, err := e.apiCall("POST", "/api/v1.4/task", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("submit task: %w", err)
	}

	var resp struct {
		Status string    `json:"status"`
		Task   MythicTask `json:"task"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse task response: %w", err)
	}

	e.mu.Lock()
	e.tasks[resp.Task.ID] = &resp.Task
	e.mu.Unlock()

	logger.Info(fmt.Sprintf("[Mythic] Task %d submitted to callback %d: %s", resp.Task.ID, callbackID, command))
	return &resp.Task, nil
}

func (e *MythicEngine) SubmitTaskDirect(callbackID int, commandString string) (*MythicTask, error) {
	return e.SubmitTask(callbackID, commandString, nil)
}

func (e *MythicEngine) GetTaskResult(taskID int) (*MythicTask, error) {
	data, err := e.apiCall("GET", fmt.Sprintf("/api/v1.4/task/%d", taskID), nil)
	if err != nil {
		return nil, fmt.Errorf("get task %d: %w", taskID, err)
	}

	var resp struct {
		Status string    `json:"status"`
		Task   MythicTask `json:"task"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse task: %w", err)
	}

	e.mu.Lock()
	e.tasks[resp.Task.ID] = &resp.Task
	e.mu.Unlock()

	return &resp.Task, nil
}

func (e *MythicEngine) GetTaskResults(callbackID int) ([]MythicTask, error) {
	data, err := e.apiCall("GET", fmt.Sprintf("/api/v1.4/task/by_callback/%d", callbackID), nil)
	if err != nil {
		return nil, fmt.Errorf("get tasks for callback %d: %w", callbackID, err)
	}

	var resp struct {
		Status string      `json:"status"`
		Tasks  []MythicTask `json:"tasks"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse tasks: %w", err)
	}

	e.mu.Lock()
	for i := range resp.Tasks {
		e.tasks[resp.Tasks[i].ID] = &resp.Tasks[i]
	}
	e.mu.Unlock()

	return resp.Tasks, nil
}

func (e *MythicEngine) ListCommands() ([]string, error) {
	data, err := e.apiCall("GET", "/api/v1.4/commands", nil)
	if err != nil {
		return nil, fmt.Errorf("list commands: %w", err)
	}

	var resp struct {
		Status   string   `json:"status"`
		Commands []string `json:"commands"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse commands: %w", err)
	}

	return resp.Commands, nil
}

func (e *MythicEngine) GetCommandInfo(commandName string) (map[string]interface{}, error) {
	data, err := e.apiCall("GET", fmt.Sprintf("/api/v1.4/commands/%s", commandName), nil)
	if err != nil {
		return nil, fmt.Errorf("get command info: %w", err)
	}

	var resp struct {
		Status  string                 `json:"status"`
		Command map[string]interface{} `json:"command"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse command info: %w", err)
	}

	return resp.Command, nil
}

func (e *MythicEngine) ListPayloads() ([]MythicPayload, error) {
	data, err := e.apiCall("GET", "/api/v1.4/payloads", nil)
	if err != nil {
		return nil, fmt.Errorf("list payloads: %w", err)
	}

	var resp struct {
		Status   string         `json:"status"`
		Payloads []MythicPayload `json:"payloads"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse payloads: %w", err)
	}

	e.mu.Lock()
	for i := range resp.Payloads {
		e.payloads[resp.Payloads[i].ID] = &resp.Payloads[i]
	}
	e.mu.Unlock()

	return resp.Payloads, nil
}

func (e *MythicEngine) UploadFile(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	fileInfo, _ := file.Stat()
	payload := map[string]interface{}{
		"filename": fileInfo.Name(),
		"data":     fileInfo.Name(),
	}
	body, _ := json.Marshal(payload)

	data, err := e.apiCall("POST", "/api/v1.4/file", strings.NewReader(string(body)))
	if err != nil {
		return 0, fmt.Errorf("upload file: %w", err)
	}

	var resp struct {
		Status string `json:"status"`
		FileID int    `json:"file_id"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0, fmt.Errorf("parse upload response: %w", err)
	}

	logger.Info(fmt.Sprintf("[Mythic] File uploaded: %s (id=%d)", filePath, resp.FileID))
	return resp.FileID, nil
}

func (e *MythicEngine) DownloadFile(fileID int, outputPath string) error {
	data, err := e.apiCall("GET", fmt.Sprintf("/api/v1.4/file/%d", fileID), nil)
	if err != nil {
		return fmt.Errorf("download file %d: %w", fileID, err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	logger.Info(fmt.Sprintf("[Mythic] File %d downloaded to %s", fileID, outputPath))
	return nil
}

func (e *MythicEngine) SearchMythic(query string) (string, error) {
	payload := map[string]string{"q": query}
	body, _ := json.Marshal(payload)

	data, err := e.apiCall("POST", "/api/v1.4/search", strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("search: %w", err)
	}

	var pretty map[string]interface{}
	json.Unmarshal(data, &pretty)
	formatted, _ := json.MarshalIndent(pretty, "", "  ")
	return string(formatted), nil
}

func (e *MythicEngine) GetEventLogs(callbackID int) (string, error) {
	data, err := e.apiCall("GET", fmt.Sprintf("/api/v1.4/event_log/%d", callbackID), nil)
	if err != nil {
		return "", fmt.Errorf("get event logs: %w", err)
	}

	var pretty map[string]interface{}
	json.Unmarshal(data, &pretty)
	formatted, _ := json.MarshalIndent(pretty, "", "  ")
	return string(formatted), nil
}

func (e *MythicEngine) apiCallRaw(method, endpoint string, body io.Reader) ([]byte, error) {
	return e.apiCall(method, endpoint, body)
}
