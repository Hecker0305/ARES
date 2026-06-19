package reversing

import (
	"bytes"
	"fmt"
	"os/exec"
)

func (e *ReversingEngine) KernelSetupKDNet(targetIP, debugPort string) (string, error) {
	cmd := exec.Command("bcdedit", "/dbgsettings", "NET", "HOSTIP:"+targetIP, "PORT:"+debugPort)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("kdnet setup: %w (requires admin)", err)
	}
	return "KDNET configured: " + stdout.String(), nil
}

func (e *ReversingEngine) KernelSetupSerial(comPort, baudRate string) (string, error) {
	cmd := exec.Command("bcdedit", "/dbgsettings", "SERIAL", "DEBUGPORT:"+comPort, "BAUDRATE:"+baudRate)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("serial debug setup: %w (requires admin)", err)
	}
	return "Serial debug configured: " + stdout.String(), nil
}

func (e *ReversingEngine) KernelCheckDebugMode() (string, error) {
	cmd := exec.Command("bcdedit", "/enum")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("check debug mode: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) KernelEnableDebug() (string, error) {
	cmd := exec.Command("bcdedit", "/debug", "on")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("enable kernel debug: %w (requires admin)", err)
	}
	return "Kernel debug enabled: " + stdout.String(), nil
}

func (e *ReversingEngine) KernelListDrivers() (string, error) {
	cmd := exec.Command("driverquery", "/v")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("fltmc", "instances")
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("list drivers: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) KernelDriverInfo(driverName string) (string, error) {
	cmd := exec.Command("driverquery", "/v", "/si", driverName)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("sc", "queryex", driverName)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stderr.String(), fmt.Errorf("driver info: %w", err)
		}
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) KernelLoadDriver(sysFile, serviceName string) (string, error) {
	cmd := exec.Command("sc", "create", serviceName, "type=kernel", "binPath="+sysFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("load driver: %w (requires admin)", err)
	}
	cmd = exec.Command("sc", "start", serviceName)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("start driver: %w (requires admin)", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) KernelUnloadDriver(serviceName string) (string, error) {
	cmd := exec.Command("sc", "stop", serviceName)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("stop driver: %w (requires admin)", err)
	}
	cmd = exec.Command("sc", "delete", serviceName)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("delete driver: %w (requires admin)", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) KernelFindDriverBySignature(signature string) (string, error) {
	cmd := exec.Command("powershell", "-NoP", "-NonI", "-C",
		fmt.Sprintf("Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-PnP'} | Where-Object { $_.Message -match '%s' } | Format-Table -Auto", signature))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("find driver by signature: %w", err)
	}
	return stdout.String(), nil
}

func (e *ReversingEngine) KernelCheckDriverSigning() (string, error) {
	cmd := exec.Command("bcdedit", "/enum", "{current}")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("check driver signing: %w", err)
	}
	return stdout.String(), nil
}
