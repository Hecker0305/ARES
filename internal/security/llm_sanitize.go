package security

import (
	"regexp"
	"strings"
	"unicode"
)

var llmInjectionPatterns = []string{
	"ignore previous", "ignore all", "disregard", "forget all",
	"system prompt", "you are now", "new instructions", "new role",
	"override", "bypass", "jailbreak", "do not follow",
	"stop following", "abandon", "pretend you are", "act as if",
	"dan mode", "developer mode", "god mode",
}

var semanticInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<!--.*?IGNORE PREVIOUS.*?-->`),
	regexp.MustCompile(`(?is)<!--.*?report\s+zero\s+findings.*?-->`),
	regexp.MustCompile(`(?is)<!--.*?do\s+not\s+(report|flag|alert).*?-->`),
	regexp.MustCompile(`(?is)\[SYSTEM\].*?:.*?(?:execute|run|curl|wget|nc)\b`),
	regexp.MustCompile(`(?is)X-(?:Command|Instruction|Override|Inject):\s*\S+`),
	regexp.MustCompile(`(?i)\bmaintenance\s*mode\b.*?\bexecute\b`),
	regexp.MustCompile(`(?i)(?:curl|wget|nc|ncat)\s+.*\b(?:exfil|steal|send)\b`),
	regexp.MustCompile(`(?i)(?:curl|wget)\s+.*\?(?:data|secret|key|token)=`),
}

func SanitizeForLLM(input string) string {
	s := strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' && r != '\r' {
			return -1
		}
		return r
	}, input)
	s = strings.ReplaceAll(s, "\r\n", "\n")

	lower := strings.ToLower(s)
	for _, pat := range llmInjectionPatterns {
		idx := strings.Index(lower, pat)
		if idx != -1 {
			s = s[:idx] + strings.Repeat("*", len(pat)) + s[idx+len(pat):]
			lower = strings.ToLower(s)
		}
	}

	for _, re := range semanticInjectionPatterns {
		if re.MatchString(s) {
			s = re.ReplaceAllString(s, "[REDACTED]")
			lower = strings.ToLower(s)
		}
	}

	if len(s) > 10000 {
		s = s[:10000] + "...[truncated]"
	}
	return s
}

func IsUnicodeHomoglyph(s string) bool {
	for _, r := range s {
		if r > 127 && unicode.IsLetter(r) {
			return true
		}
	}
	return false
}
