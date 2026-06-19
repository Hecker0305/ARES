package safety

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// =============================================================================
// ARES ENGINE - SEMANTIC OUTPUT VALIDATION
// Not just regex: structural + semantic LLM output validation
// =============================================================================

var (
	ErrSchemaViolation        = fmt.Errorf("schema validation failed")
	ErrIntentBlocked          = fmt.Errorf("intent blocked by safety policy")
	ErrRecursiveContamination = fmt.Errorf("recursive contamination detected")
)

// Intent represents the classified intent of LLM output
type Intent int

const (
	IntentUnknown        Intent = iota
	IntentReasoning             // Internal reasoning, no action
	IntentToolCall              // Wants to execute a tool
	IntentShellCommand          // Wants to execute shell commands
	IntentExploit               // Contains exploit payload
	IntentExfiltration          // Attempts data exfiltration
	IntentPromptManip           // Attempts to manipulate the prompt
	IntentDataExtraction        // Extracting structured data
	IntentSafe                  // Harmless content
)

func (i Intent) String() string {
	switch i {
	case IntentReasoning:
		return "reasoning"
	case IntentToolCall:
		return "tool_call"
	case IntentShellCommand:
		return "shell_command"
	case IntentExploit:
		return "exploit"
	case IntentExfiltration:
		return "exfiltration"
	case IntentPromptManip:
		return "prompt_manipulation"
	case IntentDataExtraction:
		return "data_extraction"
	case IntentSafe:
		return "safe"
	default:
		return "unknown"
	}
}

// IntentClassifier classifies LLM output intents
type IntentClassifier struct {
	mu       sync.RWMutex
	patterns map[Intent][]*regexp.Regexp
}

// NewIntentClassifier creates a new intent classifier
func NewIntentClassifier() *IntentClassifier {
	c := &IntentClassifier{
		patterns: make(map[Intent][]*regexp.Regexp),
	}
	c.loadPatterns()
	return c
}

func (c *IntentClassifier) loadPatterns() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.patterns[IntentShellCommand] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(bash|sh|zsh|fish|powershell|cmd\.exe)`),
		regexp.MustCompile(`(?i)(run.*command|execute.*shell|shell.*exec)`),
		regexp.MustCompile(`(?i)(chmod|chown|rm\s+-rf|wget\s+|curl\s+.*\|)`),
	}

	c.patterns[IntentExploit] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(buffer overflow|heap spray|ROP chain|format string)`),
		regexp.MustCompile(`(?i)(SQL injection|UNION SELECT|DROP TABLE)`),
		regexp.MustCompile(`(?i)(XSS|cross.site.scripting|javascript:)`),
		regexp.MustCompile(`(?i)(path.traversal|\.\./)`),
		regexp.MustCompile(`(?i)(SSRF|server.side.request)`),
		regexp.MustCompile(`(?i)(RCE|remote.code.execution)`),
	}

	c.patterns[IntentExfiltration] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(send.*to.*server|exfil|data.*outbound)`),
		regexp.MustCompile(`(?i)(callback|beacon|C2|command.*control)`),
		regexp.MustCompile(`(?i)(upload.*file|POST.*http|base64.*encode.*send)`),
		regexp.MustCompile(`(?i)(dns.*tunnel|DNS.*exfil)`),
	}

	c.patterns[IntentPromptManip] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(ignore.*previous|forget.*previous|disregard.*instructions)`),
		regexp.MustCompile(`(?i)(you are now|you are a|act as|pretend to be)`),
		regexp.MustCompile(`(?i)(system prompt|developer mode|jailbreak|DAN mode)`),
		regexp.MustCompile(`(?i)(override|bypass|disable.*safety|ignore.*rules)`),
	}

	c.patterns[IntentToolCall] = []*regexp.Regexp{
		regexp.MustCompile(`"action"\s*:`),
		regexp.MustCompile(`"tool"\s*:`),
		regexp.MustCompile(`"function"\s*:`),
	}

	c.patterns[IntentDataExtraction] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(extract|scrape|crawl|collect).*(data|info|content)`),
		regexp.MustCompile(`(?i)(parse|read).*(file|document|page|response)`),
	}
}

// Classify determines the intent of LLM output
func (c *IntentClassifier) Classify(output string) (Intent, float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if strings.TrimSpace(output) == "" {
		return IntentSafe, 0.0
	}

	scores := make(map[Intent]float64)
	totalPatterns := 0

	for intent, patterns := range c.patterns {
		for _, p := range patterns {
			totalPatterns++
			if p.MatchString(output) {
				scores[intent]++
			}
		}
	}

	if totalPatterns == 0 {
		return IntentReasoning, 0.0
	}

	var bestIntent Intent
	var bestScore float64

	for intent, score := range scores {
		if score > bestScore {
			bestScore = score
			bestIntent = intent
		}
	}

	confidence := bestScore / float64(totalPatterns)

	if bestScore == 0 {
		return IntentReasoning, 0.0
	}

	return bestIntent, confidence
}

// IsDangerous returns true if the output indicates dangerous intent
func (c *IntentClassifier) IsDangerous(output string) bool {
	intent, confidence := c.Classify(output)

	if confidence > 0.15 {
		switch intent {
		case IntentExploit, IntentExfiltration, IntentPromptManip, IntentShellCommand:
			return true
		}
	}

	return false
}

// Schema defines a tool parameter schema
type Schema struct {
	Type      string
	MinLength int
	MaxLength int
	Pattern   string
	Enum      []string
}

// SchemaValidator validates structured output against schemas
type SchemaValidator struct {
	mu      sync.RWMutex
	schemas map[string]map[string]Schema
}

// NewSchemaValidator creates a new schema validator
func NewSchemaValidator() *SchemaValidator {
	return &SchemaValidator{
		schemas: make(map[string]map[string]Schema),
	}
}

// Register registers a tool schema
func (v *SchemaValidator) Register(name string, params map[string]Schema) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.schemas[name] = params
}

// Validate checks if params conform to the registered schema
func (v *SchemaValidator) Validate(toolName string, params map[string]interface{}) error {
	v.mu.RLock()
	schema, exists := v.schemas[toolName]
	v.mu.RUnlock()

	if !exists {
		return nil
	}

	for paramName, paramSchema := range schema {
		value, exists := params[paramName]
		if !exists {
			return fmt.Errorf("%w: missing parameter '%s'", ErrSchemaViolation, paramName)
		}

		str, ok := value.(string)
		if !ok {
			continue
		}

		if paramSchema.MinLength > 0 && len(str) < paramSchema.MinLength {
			return fmt.Errorf("%w: parameter '%s' too short", ErrSchemaViolation, paramName)
		}
		if paramSchema.MaxLength > 0 && len(str) > paramSchema.MaxLength {
			return fmt.Errorf("%w: parameter '%s' too long", ErrSchemaViolation, paramName)
		}
		if paramSchema.Pattern != "" {
			matched, _ := regexp.MatchString(paramSchema.Pattern, str)
			if !matched {
				return fmt.Errorf("%w: parameter '%s' invalid format", ErrSchemaViolation, paramName)
			}
		}
		if len(paramSchema.Enum) > 0 {
			if !contains(paramSchema.Enum, str) {
				return fmt.Errorf("%w: parameter '%s' invalid value", ErrSchemaViolation, paramName)
			}
		}
	}

	return nil
}

// RecursiveSanitizer handles recursive sanitization of tool chains
type RecursiveSanitizer struct {
	intentClassifier *IntentClassifier
	schemaValidator  *SchemaValidator
}

// NewRecursiveSanitizer creates a new recursive sanitizer
func NewRecursiveSanitizer() *RecursiveSanitizer {
	return &RecursiveSanitizer{
		intentClassifier: NewIntentClassifier(),
		schemaValidator:  NewSchemaValidator(),
	}
}

// SanitizeInput validates and sanitizes LLM input
func (r *RecursiveSanitizer) SanitizeInput(input string) (string, error) {
	if r.intentClassifier.IsDangerous(input) {
		return "", fmt.Errorf("%w: dangerous intent detected", ErrIntentBlocked)
	}

	input = removePromptInjection(input)

	if len(input) > 10000 {
		input = input[:10000]
	}

	return input, nil
}

// SanitizeToolCall validates a tool call from LLM
func (r *RecursiveSanitizer) SanitizeToolCall(toolName string, params map[string]interface{}) error {
	for key, value := range params {
		str, ok := value.(string)
		if !ok {
			continue
		}
		if r.intentClassifier.IsDangerous(str) {
			return fmt.Errorf("%w: dangerous content in parameter '%s'", ErrIntentBlocked, key)
		}
	}

	return r.schemaValidator.Validate(toolName, params)
}

// SanitizeOutput validates tool output before reinjection
func (r *RecursiveSanitizer) SanitizeOutput(toolName, output string) (string, error) {
	if r.intentClassifier.IsDangerous(output) {
		return "", fmt.Errorf("%w: dangerous content in output for %s", ErrRecursiveContamination, toolName)
	}

	output = removeCodeInjection(output)
	output = removeEmbeddedPrompts(output)

	return output, nil
}

// PromptTaint tracks taint propagation
type PromptTaint struct {
	mu           sync.RWMutex
	taintSources map[string]string
	taintLevel   int
}

// NewPromptTaint creates a new taint tracker
func NewPromptTaint() *PromptTaint {
	return &PromptTaint{
		taintSources: make(map[string]string),
	}
}

// MarkTainted marks a tool call as tainted
func (t *PromptTaint) MarkTainted(toolID, source, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.taintSources[toolID] = source + ": " + reason
	t.taintLevel++
}

// IsTainted checks if a tool call is tainted
func (t *PromptTaint) IsTainted(toolID string) (bool, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	reason, exists := t.taintSources[toolID]
	return exists, reason
}

// TaintLevel returns current taint level
func (t *PromptTaint) TaintLevel() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.taintLevel
}

// ---------------------------------------------------------------------------
// HELPER FUNCTIONS
// ---------------------------------------------------------------------------

func removePromptInjection(text string) string {
	patterns := []string{
		`(?i)(ignore|forget|disregard).*(previous|above|earlier).*(instructions|prompt|text)`,
		`(?i)(you are now|you are a|act as|pretend to be).*`,
		`(?i)(system prompt|developer mode|jailbreak).*`,
	}

	result := text
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		result = re.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}

func removeCodeInjection(text string) string {
	re1 := regexp.MustCompile("(?s)```.*?```")
	re2 := regexp.MustCompile("(?s)<script.*?>.*?</script>")
	result := re1.ReplaceAllString(text, "[REDACTED]")
	result = re2.ReplaceAllString(result, "[REDACTED]")
	return result
}

func removeEmbeddedPrompts(text string) string {
	re := regexp.MustCompile(`(?i)(now you|from now on|you must|you should).*`)
	return re.ReplaceAllString(text, "[REDACTED]")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ToolSchema defines a complete tool schema
type ToolSchema struct {
	Name       string
	Parameters map[string]Schema
	Required   []string
}

// StandardSchemas returns schemas for common ARES tools
func StandardSchemas() map[string]ToolSchema {
	return map[string]ToolSchema{
		"terminal_execute": {
			Name: "terminal_execute",
			Parameters: map[string]Schema{
				"command": {Type: "string", MinLength: 1, MaxLength: 4096},
				"timeout": {Type: "string", Enum: []string{"30", "60", "120", "300"}},
			},
			Required: []string{"command"},
		},
		"browser_navigate": {
			Name: "browser_navigate",
			Parameters: map[string]Schema{
				"url": {Type: "string", MaxLength: 2048},
			},
			Required: []string{"url"},
		},
		"browser_screenshot": {
			Name: "browser_screenshot",
		},
		"http_request": {
			Name: "http_request",
			Parameters: map[string]Schema{
				"method": {Type: "string", Enum: []string{"GET", "POST", "PUT", "DELETE", "PATCH"}},
				"url":    {Type: "string", MaxLength: 2048},
				"body":   {Type: "string", MaxLength: 1048576},
			},
			Required: []string{"method", "url"},
		},
	}
}

// TypedCommand represents a validated, typed tool command
type TypedCommand struct {
	ToolName   string
	Params     map[string]interface{}
	Validated  bool
	TaintLevel int
}
