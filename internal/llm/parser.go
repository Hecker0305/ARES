package llm

import (
	"html"
	"regexp"
	"strings"
	"unicode"
)

type ToolCall struct {
	Name string            `json:"name"`
	Args map[string]string `json:"args"`
}

var (
	fnRegex        = regexp.MustCompile(`(?s)<function=([^>]+)>\n?(.*?)</function>`)
	paramEqRegex   = regexp.MustCompile(`(?s)<parameter=([^>]+)>(.*?)</parameter>`)
	paramSpRegex   = regexp.MustCompile(`(?s)<parameter\s+([^=>]+)>(.*?)</parameter>`)
	paramAttrRegex = regexp.MustCompile(`(?s)<parameter\s+name=["']([^"']+)["']>(.*?)</parameter>`)
	invokeOpen     = regexp.MustCompile(`<invoke\s+name=["']([^"']+)["']>`)
	funcCallsTag   = regexp.MustCompile(`</?function_calls>`)
	stripQuotesRe  = regexp.MustCompile(`<(function|parameter)\s*=\s*["']?([^>"']+?)["']?\s*>`)
	toolPattern    = regexp.MustCompile(`(?s)<function=[^>]+>.*?</function>`)
	incompleteFunc = regexp.MustCompile(`(?s)<function=[^>]+>.*$`)
	interAgentRe   = regexp.MustCompile(`(?is)<inter_agent_message>.*?</inter_agent_message>`)
	agentReportRe  = regexp.MustCompile(`(?is)<agent_completion_report>.*?</agent_completion_report>`)
	multiBlankRe   = regexp.MustCompile(`\n\s*\n`)
	lenientParamRe = regexp.MustCompile(`(?s)<parameter[^>]*?(\w+)\s*>(.*?)</parameter>`)
	identSplitRe   = regexp.MustCompile(`[.\s,;:!?]+`)
)

const maxLLMToolCallInput = 100000

func ParseToolCalls(content string) []ToolCall {
	if len(content) > maxLLMToolCallInput {
		content = content[:maxLLMToolCallInput]
	}
	content = normalizeFormat(content)
	content = fixIncomplete(content)
	content = limitBracketDepth(content, 15)

	var calls []ToolCall
	for _, match := range fnRegex.FindAllStringSubmatch(content, -1) {
		fnName := sanitizeParamName(strings.TrimSpace(match[1]))
		if fnName == "" {
			continue
		}
		body := match[2]
		args := extractParams(body)
		calls = append(calls, ToolCall{Name: fnName, Args: args})
	}
	return calls
}

func extractParams(body string) map[string]string {
	args := make(map[string]string)
	regexes := []*regexp.Regexp{paramEqRegex, paramAttrRegex, paramSpRegex}
	for _, re := range regexes {
		matches := re.FindAllStringSubmatch(body, -1)
		if len(matches) > 0 {
			for _, pm := range matches {
				pName := sanitizeParamName(pm[1])
				if pName == "" {
					continue
				}
				args[pName] = html.UnescapeString(strings.TrimSpace(pm[2]))
			}
			if len(args) > 0 {
				return args
			}
		}
	}
	for _, pm := range lenientParamRe.FindAllStringSubmatch(body, -1) {
		pName := sanitizeParamName(pm[1])
		if pName != "" {
			args[pName] = html.UnescapeString(strings.TrimSpace(pm[2]))
		}
	}
	if len(args) > 0 {
		return args
	}
	trimmed := strings.TrimSpace(body)
	if trimmed != "" && !strings.Contains(trimmed, "<") {
		args["_raw"] = trimmed
	}
	return args
}

func limitBracketDepth(s string, maxDepth int) string {
	depth := 0
	var result strings.Builder
	for _, r := range s {
		if r == '<' {
			depth++
			if depth > maxDepth {
				continue
			}
		}
		if r == '>' {
			if depth <= maxDepth {
				result.WriteRune(r)
			}
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth <= maxDepth {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func sanitizeParamName(raw string) string {
	raw = strings.TrimSpace(raw)
	if isIdentifier(raw) {
		return raw
	}
	parts := identSplitRe.Split(raw, -1)
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if isIdentifier(p) {
			return p
		}
	}
	return ""
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 && !unicode.IsLetter(r) && r != '_' {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

func normalizeFormat(content string) string {
	if strings.Contains(content, "<invoke") || strings.Contains(content, "<function_calls") {
		content = funcCallsTag.ReplaceAllString(content, "")
		content = invokeOpen.ReplaceAllString(content, "<function=$1>")
		content = strings.ReplaceAll(content, "</invoke>", "</function>")
	}
	content = stripQuotesRe.ReplaceAllStringFunc(content, func(s string) string {
		m := stripQuotesRe.FindStringSubmatch(s)
		if len(m) < 3 {
			return s
		}
		val := strings.TrimSpace(m[2])
		return "<" + m[1] + "=" + val + ">"
	})
	return content
}

func fixIncomplete(content string) string {
	countOpen := strings.Count(content, "<function=") + strings.Count(content, "<invoke ")
	countClose := strings.Count(content, "</function>") + strings.Count(content, "</invoke>")
	if countOpen <= countClose {
		return content
	}
	content = strings.TrimRight(content, " \t\n\r")
	if strings.HasSuffix(content, "</") {
		return content + "function>"
	}
	return content + "\n</function>"
}

func FormatToolCall(name string, args map[string]string) string {
	var b strings.Builder
	b.WriteString("<function=")
	b.WriteString(name)
	b.WriteString(">\n")
	for k, v := range args {
		b.WriteString("<parameter=")
		b.WriteString(k)
		b.WriteString(">")
		b.WriteString(html.EscapeString(v))
		b.WriteString("</parameter>\n")
	}
	b.WriteString("</function>")
	return b.String()
}

func CleanContent(content string) string {
	content = normalizeFormat(content)
	content = fixIncomplete(content)
	cleaned := toolPattern.ReplaceAllString(content, "")
	cleaned = incompleteFunc.ReplaceAllString(cleaned, "")
	cleaned = interAgentRe.ReplaceAllString(cleaned, "")
	cleaned = agentReportRe.ReplaceAllString(cleaned, "")
	cleaned = multiBlankRe.ReplaceAllString(cleaned, "\n\n")
	return strings.TrimSpace(cleaned)
}
