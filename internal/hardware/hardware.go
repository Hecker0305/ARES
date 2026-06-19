package hardware

import (
	"fmt"
	"os/exec"
)

// O1 — Firmware / UEFI Analysis
type FirmwareAnalyzer struct{}

func NewFirmwareAnalyzer() *FirmwareAnalyzer {
	return &FirmwareAnalyzer{}
}

func (f *FirmwareAnalyzer) ExtractFirmware(imagePath, outputDir string) error {
	cmd := exec.Command("binwalk", "-e", "-M", "-r", "-q", "-C", outputDir, imagePath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("binwalk extract: %w", err)
	}
	return nil
}

func (f *FirmwareAnalyzer) ScanHardcodedCreds(firmwarePath string) (string, error) {
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("strings %s | grep -iE '(password|secret|key|token|credential|passwd)' | head -50", firmwarePath))
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("strings scan: %w", err)
	}
	return string(output), nil
}

// O2 — Bluetooth / RF Attack Surface
type RFAttackSurface struct{}

func NewRFAttackSurface() *RFAttackSurface {
	return &RFAttackSurface{}
}

func (r *RFAttackSurface) ScanBluetoothDevices() (string, error) {
	cmd := exec.Command("hcitool", "scan")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("bluetooth scan: %w", err)
	}
	return string(output), nil
}

func (r *RFAttackSurface) BLEGATTServices(deviceAddr string) (string, error) {
	cmd := exec.Command("gatttool", "-b", deviceAddr, "--primary")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("BLE GATT: %w", err)
	}
	return string(output), nil
}

// O3 — Hardware Interface Testing
type HardwareTester struct{}

func NewHardwareTester() *HardwareTester {
	return &HardwareTester{}
}

func (h *HardwareTester) DetectDebugInterfaces() []string {
	var interfaces []string
	paths := []string{
		"/dev/ttyUSB0", "/dev/ttyACM0", "/dev/ttyAMA0",
		"/dev/ttyS0", "/dev/ttyS1", "/dev/ttyS2",
	}
	for _, p := range paths {
		if _, err := exec.Command("sh", "-c", "test -c "+p).Output(); err == nil {
			interfaces = append(interfaces, p)
		}
	}
	return interfaces
}

func (h *HardwareTester) ProbeUART(device string, baud int) error {
	cmd := exec.Command("stty", "-F", device, fmt.Sprintf("%d", baud), "cs8", "-cstopb", "-parenb")
	return cmd.Run()
}
