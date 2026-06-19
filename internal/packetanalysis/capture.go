package packetanalysis

import (
	"fmt"
)

func StartLiveCapture(interfaceName string, config CaptureConfig) (string, error) {
	args := []string{"-i", interfaceName, "-w", config.OutputFile}
	if config.Duration > 0 {
		args = append(args, "-a", fmt.Sprintf("duration:%d", config.Duration))
	}
	if config.Filter != "" {
		args = append(args, "-f", config.Filter)
	}
	if config.PacketCount > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", config.PacketCount))
	}
	if config.SnapLen > 0 {
		args = append(args, "-s", fmt.Sprintf("%d", config.SnapLen))
	}
	if !config.Promiscuous {
		args = append(args, "-p")
	}
	return runCapture(args...)
}

func StopCapture() (string, error) {
	return runCapture("-k")
}

func CaptureToFile(interfaceName, outputFile string, duration int) (string, error) {
	return runCapture("-i", interfaceName, "-w", outputFile, "-a", fmt.Sprintf("duration:%d", duration))
}

func CaptureWithFilter(interfaceName, bpfFilter, outputFile string, packetCount int) (string, error) {
	args := []string{"-i", interfaceName, "-w", outputFile, "-f", bpfFilter}
	if packetCount > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", packetCount))
	}
	return runCapture(args...)
}

func CaptureOffline(pcapFile string) (string, error) {
	return runCapture("-r", pcapFile)
}

func CaptureHTTPTraffic(interfaceName, outputFile string) (string, error) {
	return runCapture("-i", interfaceName, "-Y", "http", "-w", outputFile)
}

func CaptureDNSTraffic(interfaceName, outputFile string) (string, error) {
	return runCapture("-i", interfaceName, "-Y", "dns", "-w", outputFile)
}

func CaptureKerberosTraffic(interfaceName, outputFile string) (string, error) {
	return runCapture("-i", interfaceName, "-Y", "kerberos", "-w", outputFile)
}

func CaptureSMBAuth(interfaceName, outputFile string) (string, error) {
	return runCapture("-i", interfaceName, "-Y", "smb or smb2", "-w", outputFile)
}
