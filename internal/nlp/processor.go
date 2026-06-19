package nlp

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

type Intent string

const (
	IntentScan       Intent = "scan"
	IntentExploit    Intent = "exploit"
	IntentEnumerate  Intent = "enumerate"
	IntentEscalate   Intent = "escalate"
	IntentPivot      Intent = "pivot"
	IntentExfiltrate Intent = "exfiltrate"
	IntentCleanup    Intent = "cleanup"
	IntentHelp       Intent = "help"
	IntentStatus     Intent = "status"
	IntentUnknown    Intent = "unknown"
)

type Entity struct {
	Type  string
	Value string
	Start int
	End   int
}

type ProcessedInput struct {
	Intent     Intent
	Entities   []Entity
	Confidence float64
	Original   string
	Flags      []string
}

type intentProfile struct {
	keywords []string
	weight   float64
}

type Processor struct {
	intentProfiles map[Intent]intentProfile
	regexEntities  []regexEntity
	stopWords      map[string]bool
	fuzzyThreshold int
}

type regexEntity struct {
	Type  string
	Regex *regexp.Regexp
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["']?[^"'\s\n]{1,128}["']?`),
	regexp.MustCompile(`(?i)(secret|token|api_key|apikey)\s*[:=]\s*["']?[^"'\s\n]{1,256}["']?`),
	regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
	regexp.MustCompile(`pk-[a-zA-Z0-9]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`gh[pousr]_[a-zA-Z0-9]{36,}`),
	regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`),
}

func redactSecrets(input string) string {
	result := input
	for _, p := range secretPatterns {
		result = p.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}

func NewProcessor() *Processor {
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "is": true, "are": true,
		"was": true, "were": true, "be": true, "been": true, "being": true,
		"have": true, "has": true, "had": true, "do": true, "does": true,
		"did": true, "will": true, "would": true, "could": true, "should": true,
		"may": true, "might": true, "shall": true, "can": true, "need": true,
		"to": true, "of": true, "in": true, "for": true, "on": true,
		"with": true, "at": true, "by": true, "from": true, "as": true,
		"into": true, "through": true, "during": true, "before": true,
		"after": true, "above": true, "below": true, "between": true,
		"and": true, "or": true, "but": true, "if": true, "because": true,
		"so": true, "than": true, "that": true, "this": true, "these": true,
		"those": true, "it": true, "its": true, "i": true, "me": true,
		"my": true, "we": true, "our": true, "you": true, "your": true,
		"he": true, "she": true, "they": true, "them": true, "their": true,
		"what": true, "which": true, "who": true, "how": true, "when": true,
		"where": true, "why": true, "please": true, "just": true, "not": true,
		"no": true, "yes": true, "ok": true, "okay": true, "all": true,
		"any": true, "each": true, "every": true, "both": true, "few": true,
		"more": true, "most": true, "other": true, "some": true, "such": true,
		"only": true, "own": true, "same": true,
		"too": true, "very": true, "about": true, "up": true, "out": true,
	}

	ipv4Regex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	urlRegex := regexp.MustCompile(`\bhttps?://[^\s/$.?#]+\.[^\s]*\b`)
	domainRegex := regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	portRegex := regexp.MustCompile(`\bport\s+(\d+)\b|\b(\d+)\/(?:tcp|udp)\b`)
	emailRegex := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	pathRegex := regexp.MustCompile(`(?:/[a-zA-Z0-9_.-]+)+`)
	cveRegex := regexp.MustCompile(`\bCVE-\d{4}-\d{4,7}\b`)
	ipRangeRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`)
	hashRegex := regexp.MustCompile(`\b[0-9a-fA-F]{32,64}\b`)

	return &Processor{
		intentProfiles: map[Intent]intentProfile{
			IntentScan: {
				keywords: []string{"scan", "test", "check", "assess", "evaluate", "probe",
					"enumerate", "survey", "fingerprint", "banner", "portscan"},
				weight: 1.0,
			},
			IntentExploit: {
				keywords: []string{"exploit", "hack", "penetrate", "breach", "infiltrate",
					"compromise", "pwning", "shell", "rce", "execute"},
				weight: 1.2,
			},
			IntentEnumerate: {
				keywords: []string{"enumerate", "list", "dump", "extract", "gather",
					"collect", "harvest", "sniff", "capture", "discover"},
				weight: 0.9,
			},
			IntentEscalate: {
				keywords: []string{"escalate", "privilege", "root", "admin", "sudo",
					"suid", "elevate", "uac", "bypass", "impersonate"},
				weight: 1.3,
			},
			IntentPivot: {
				keywords: []string{"pivot", "lateral", "move", "jump", "transfer",
					"relay", "tunnel", "proxy", "hop", "bridge"},
				weight: 1.1,
			},
			IntentExfiltrate: {
				keywords: []string{"exfiltrate", "steal", "leak", "download", "upload",
					"transfer", "drain", "copy", "smuggle", "encrypt"},
				weight: 1.4,
			},
			IntentCleanup: {
				keywords: []string{"clean", "cleanup", "remove", "delete", "erase",
					"wipe", "purge", "clear", "reset", "restore"},
				weight: 0.8,
			},
			IntentHelp: {
				keywords: []string{"help", "assist", "guide", "support", "tutorial",
					"instruction", "manual", "docs", "example", "usage"},
				weight: 0.7,
			},
			IntentStatus: {
				keywords: []string{"status", "state", "condition", "health", "progress",
					"report", "summary", "overview", "dashboard", "metrics"},
				weight: 0.7,
			},
		},
		regexEntities: []regexEntity{
			{Type: "ip_range", Regex: ipRangeRegex},
			{Type: "ip", Regex: ipv4Regex},
			{Type: "url", Regex: urlRegex},
			{Type: "domain", Regex: domainRegex},
			{Type: "port", Regex: portRegex},
			{Type: "email", Regex: emailRegex},
			{Type: "path", Regex: pathRegex},
			{Type: "cve", Regex: cveRegex},
			{Type: "hash", Regex: hashRegex},
		},
		stopWords:      stopWords,
		fuzzyThreshold: 2,
	}
}

func (p *Processor) Process(input string) ProcessedInput {
	redacted := redactSecrets(input)
	input = strings.ToLower(strings.TrimSpace(redacted))
	if input == "" {
		pi := ProcessedInput{Intent: IntentUnknown, Confidence: 0.0, Original: redacted}
		pi.Clear()
		return pi
	}

	tokens := p.tokenize(input)
	tokens = p.filterStopWords(tokens)

	intent, intentConfidence, intentFlags := p.detectWithTFIDF(tokens, input)
	regexEntities := p.extractRegexEntities(input)
	keywordEntities := p.extractKeywordEntities(input)
	entities := mergeEntities(regexEntities, keywordEntities)

	flags := intentFlags
	if len(regexEntities) > 0 {
		flags = append(flags, "has_regex_entities")
	}

	confidence := p.calibrateConfidence(intentConfidence, len(entities), len(tokens))

	return ProcessedInput{
		Intent:     intent,
		Entities:   entities,
		Confidence: confidence,
		Original:   redacted,
		Flags:      flags,
	}
}

func (p *ProcessedInput) Clear() {
	p.Original = ""
	p.Entities = nil
	p.Flags = nil
}

func (p *Processor) tokenize(input string) []string {
	var tokens []string
	var current strings.Builder
	for _, r := range input {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current.WriteRune(r)
		} else {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

func (p *Processor) filterStopWords(tokens []string) []string {
	filtered := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if !p.stopWords[t] {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)

	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}

	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(curr[j-1]+1, min(prev[j]+1, prev[j-1]+cost))
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func (p *Processor) fuzzyMatch(token string, keywords []string) (string, bool) {
	bestKeyword := ""
	bestDist := p.fuzzyThreshold + 1
	for _, kw := range keywords {
		dist := levenshteinDistance(token, kw)
		if dist < bestDist || (dist == bestDist && len(kw) < len(bestKeyword)) {
			bestDist = dist
			bestKeyword = kw
		}
	}
	if bestDist <= p.fuzzyThreshold {
		return bestKeyword, true
	}
	return "", false
}

func (p *Processor) detectWithTFIDF(tokens []string, rawInput string) (Intent, float64, []string) {
	bestIntent := IntentUnknown
	bestScore := 0.0
	var flags []string

	totalTokens := len(tokens)
	if totalTokens == 0 {
		totalTokens = 1
	}

	intentScores := make(map[Intent]float64)

	for intent, profile := range p.intentProfiles {
		score := 0.0
		exactMatches := 0
		fuzzyMatches := 0

		for _, token := range tokens {
			matched := false
			for _, kw := range profile.keywords {
				if token == kw {
					score += profile.weight * 1.5
					exactMatches++
					matched = true
					break
				}
			}
			if !matched {
				if _, found := p.fuzzyMatch(token, profile.keywords); found {
					score += profile.weight * 0.7
					fuzzyMatches++
				}
			}
		}

		for _, kw := range profile.keywords {
			if strings.Contains(rawInput, kw) {
				score += profile.weight * 0.5
			}
		}

		tf := score / float64(totalTokens)
		idf := math.Log(1.0 + float64(len(p.intentProfiles))/float64(1+len(profile.keywords)))
		tfidf := tf * idf

		intentScores[intent] = tfidf

		if exactMatches > 0 {
			flags = append(flags, "exact_"+string(intent))
		}
		if fuzzyMatches > 0 {
			flags = append(flags, "fuzzy_"+string(intent))
		}
	}

	for intent, score := range intentScores {
		if score > bestScore {
			bestScore = score
			bestIntent = intent
		}
	}

	if bestScore < 0.05 {
		return IntentUnknown, 0.0, flags
	}

	sigmoid := 1.0 / (1.0 + math.Exp(-10.0*(bestScore-0.15)))
	return bestIntent, sigmoid, flags
}

func (p *Processor) calibrateConfidence(rawConfidence float64, entityCount, tokenCount int) float64 {
	if rawConfidence <= 0 {
		return 0.0
	}

	entityBonus := float64(entityCount) * 0.05
	if entityBonus > 0.3 {
		entityBonus = 0.3
	}

	tokenBonus := float64(tokenCount) * 0.02
	if tokenBonus > 0.2 {
		tokenBonus = 0.2
	}

	calibrated := rawConfidence + entityBonus + tokenBonus
	if calibrated > 1.0 {
		calibrated = 1.0
	}
	return calibrated
}

func (p *Processor) extractRegexEntities(input string) []Entity {
	var entities []Entity
	seen := make(map[string]bool)

	for _, re := range p.regexEntities {
		matches := re.Regex.FindAllStringSubmatch(input, -1)
		locs := re.Regex.FindAllStringIndex(input, -1)

		for i, matchGroup := range matches {
			var value string
			if len(matchGroup) > 1 {
				for _, g := range matchGroup[1:] {
					if g != "" {
						value = g
						break
					}
				}
			}
			if value == "" {
				value = matchGroup[0]
			}

			dedupKey := re.Type + ":" + value
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true

			start := 0
			end := len(value)
			if i < len(locs) {
				start = locs[i][0]
				end = locs[i][1]
			}

			entities = append(entities, Entity{
				Type:  re.Type,
				Value: value,
				Start: start,
				End:   end,
			})
		}
	}
	return entities
}

func (p *Processor) extractKeywordEntities(input string) []Entity {
	type entityDef struct {
		etype    string
		keywords []string
	}
	defs := []entityDef{
		{"target", []string{"target", "host", "domain", "ip", "url", "website", "endpoint", "server"}},
		{"parameter", []string{"parameter", "param", "field", "input", "variable", "argument", "header", "cookie"}},
		{"payload", []string{"payload", "exploit", "attack", "vector", "technique", "shellcode"}},
		{"technique", []string{"technique", "method", "approach", "strategy", "tactic", "procedure"}},
		{"file", []string{"file", "document", "data", "artifact", "binary", "executable"}},
		{"port", []string{"port", "endpoint", "service", "listener", "socket"}},
		{"credential", []string{"credential", "password", "username", "login", "auth", "token", "secret", "apikey"}},
		{"protocol", []string{"http", "https", "tcp", "udp", "dns", "smtp", "ssh", "ftp", "smb", "ldap", "rdp"}},
		{"vuln_type", []string{"sqli", "xss", "csrf", "ssrf", "rce", "lfi", "rfi", "idor", "xxe", "deserialization"}},
	}

	var entities []Entity
	seen := make(map[string]bool)

	for _, def := range defs {
		for _, kw := range def.keywords {
			idx := strings.Index(input, kw)
			if idx != -1 {
				key := def.etype + ":" + kw
				if seen[key] {
					continue
				}
				seen[key] = true
				entities = append(entities, Entity{
					Type:  def.etype,
					Value: kw,
					Start: idx,
					End:   idx + len(kw),
				})
			}
		}
	}
	return entities
}

func mergeEntities(a, b []Entity) []Entity {
	seen := make(map[string]bool)
	result := make([]Entity, 0, len(a)+len(b))
	for _, e := range a {
		key := e.Type + ":" + e.Value
		if !seen[key] {
			seen[key] = true
			result = append(result, e)
		}
	}
	for _, e := range b {
		key := e.Type + ":" + e.Value
		if !seen[key] {
			seen[key] = true
			result = append(result, e)
		}
	}
	return result
}
