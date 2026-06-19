package bloodhound

import (
	"fmt"
	"os/exec"
	"strings"
)

func CollectAll(targetDomain, dcIP, username, password string) (string, error) {
	args := []string{
		"-d", targetDomain,
		"-dc", dcIP,
		"-u", username,
		"-p", password,
		"-c", "All",
	}
	out, err := exec.Command("bloodhound-python", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("bloodhound-python collect all failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func CollectWithCollectionMethod(targetDomain, dcIP, username, password, method string) (string, error) {
	args := []string{
		"-d", targetDomain,
		"-dc", dcIP,
		"-u", username,
		"-p", password,
		"-c", method,
	}
	out, err := exec.Command("bloodhound-python", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("bloodhound-python collect method %s failed: %w\n%s", method, err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func CollectWithLMHash(targetDomain, dcIP, username, lmHash, method string) (string, error) {
	args := []string{
		"-d", targetDomain,
		"-dc", dcIP,
		"-u", username,
		"--hashes", lmHash,
		"-c", method,
	}
	out, err := exec.Command("bloodhound-python", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("bloodhound-python collect with lm hash failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func CollectWithKerberos(targetDomain, dcIP string) (string, error) {
	args := []string{
		"-d", targetDomain,
		"-dc", dcIP,
		"--use-kcache",
	}
	out, err := exec.Command("bloodhound-python", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("bloodhound-python collect with kerberos failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func CollectAzure(appId, secret, tenant string) (string, error) {
	args := []string{
		"--client-id", appId,
		"--client-secret", secret,
		"--tenant", tenant,
	}
	out, err := exec.Command("azurehound", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("azurehound collect failed: %w\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}
