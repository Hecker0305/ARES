package spiderfoot

import (
	"fmt"
	"os"
)

func ScanCLI(target, moduleList, outputFile string) (string, error) {
	args := []string{"-s", target, "-m", moduleList, "-o", outputFile}
	result, err := runCLI(args)
	if err != nil {
		return "", fmt.Errorf("ScanCLI failed: %w", err)
	}
	return result, nil
}

func ScanAllModules(target, outputFile string) (string, error) {
	out, err := runCLI([]string{"-s", target, "-f", "html"})
	if err != nil {
		return "", fmt.Errorf("ScanAllModules failed: %w", err)
	}
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(out), 0644); err != nil {
			return "", fmt.Errorf("failed to write output file: %w", err)
		}
	}
	return out, nil
}

func ScanByType(target, scanType, outputFile string) (string, error) {
	args := []string{"-s", target, "-t", scanType, "-o", outputFile}
	result, err := runCLI(args)
	if err != nil {
		return "", fmt.Errorf("ScanByType failed: %w", err)
	}
	return result, nil
}

func ScanWithTimeout(target string, timeoutMins int, outputFile string) (string, error) {
	args := []string{"-s", target, "-l", fmt.Sprintf("%d", timeoutMins), "-o", outputFile}
	result, err := runCLI(args)
	if err != nil {
		return "", fmt.Errorf("ScanWithTimeout failed: %w", err)
	}
	return result, nil
}
