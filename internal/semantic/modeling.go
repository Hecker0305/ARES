package semantic

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/ares/engine/internal/llm"
)

type EndpointModel struct {
	Path         string
	Method       string
	Purpose      string
	Threat       string
	RiskLevel    string
	DataType     string
	AuthRequired bool
	Confidence   float64
}

type AppModel struct {
	Target      string
	Endpoints   []EndpointModel
	TechStack   []string
	Frameworks  []string
	GeneratedAt time.Time
}

type endpointClassifier struct {
	keywords   []string
	pathRegex  *regexp.Regexp
	purpose    string
	threat     string
	risk       string
	dataType   string
	baseWeight float64
}

var purposeClassifiers = []endpointClassifier{
	{
		keywords:   []string{"user", "account", "profile", "me"},
		pathRegex:  regexp.MustCompile(`/(api/)?(users?|accounts?|profiles?|me)(/|$)`),
		purpose:    "user-identity",
		threat:     "account-takeover,privilege-escalation",
		risk:       "high",
		dataType:   "pii",
		baseWeight: 1.0,
	},
	{
		keywords:   []string{"payment", "order", "checkout", "invoice", "billing"},
		pathRegex:  regexp.MustCompile(`/(api/)?(payments?|orders?|checkout|invoices?|billing)(/|$)`),
		purpose:    "financial",
		threat:     "fraud,data-theft",
		risk:       "critical",
		dataType:   "financial",
		baseWeight: 1.5,
	},
	{
		keywords:   []string{"admin", "manage", "dashboard", "control"},
		pathRegex:  regexp.MustCompile(`/(api/)?(admin|manage|dashboard|control|console)(/|$)`),
		purpose:    "admin-panel",
		threat:     "privilege-escalation,unauthorized-access",
		risk:       "critical",
		dataType:   "admin",
		baseWeight: 1.5,
	},
	{
		keywords:   []string{"search", "query", "find", "filter"},
		pathRegex:  regexp.MustCompile(`/(api/)?(search|query|find|filter)(/|$|\?)`),
		purpose:    "search",
		threat:     "data-exfiltration,information-disclosure",
		risk:       "medium",
		dataType:   "user-content",
		baseWeight: 0.8,
	},
	{
		keywords:   []string{"upload", "file", "document", "image", "avatar"},
		pathRegex:  regexp.MustCompile(`/(api/)?(upload|files?|documents?|images?|avatars?)(/|$)`),
		purpose:    "file-handling",
		threat:     "rce,malware-upload,xss",
		risk:       "high",
		dataType:   "user-generated",
		baseWeight: 1.2,
	},
	{
		keywords:   []string{"message", "comment", "post", "review", "feedback"},
		pathRegex:  regexp.MustCompile(`/(api/)?(messages?|comments?|posts?|reviews?|feedback)(/|$)`),
		purpose:    "user-content",
		threat:     "xss,ssti,injection",
		risk:       "medium",
		dataType:   "user-content",
		baseWeight: 0.7,
	},
	{
		keywords:   []string{"api", "graphql", "rest", "data", "fetch"},
		pathRegex:  regexp.MustCompile(`/(api|graphql|rest|data|fetch)(/|$)`),
		purpose:    "api-endpoint",
		threat:     "mass-assignment,idor,auth-bypass",
		risk:       "high",
		dataType:   "api",
		baseWeight: 1.0,
	},
	{
		keywords:   []string{"auth", "login", "signin", "token", "refresh", "logout"},
		pathRegex:  regexp.MustCompile(`/(api/)?(auth|login|signin|tokens?|refresh|logout|oauth)(/|$)`),
		purpose:    "authentication",
		threat:     "auth-bypass,token-theft,credential-stuffing",
		risk:       "high",
		dataType:   "auth",
		baseWeight: 1.3,
	},
	{
		keywords:   []string{"report", "export", "download", "csv", "pdf"},
		pathRegex:  regexp.MustCompile(`/(api/)?(reports?|exports?|downloads?|csv|pdf)(/|$|\?)`),
		purpose:    "data-export",
		threat:     "information-disclosure,sao",
		risk:       "medium",
		dataType:   "exported-data",
		baseWeight: 0.6,
	},
	{
		keywords:   []string{"notification", "email", "sms", "webhook"},
		pathRegex:  regexp.MustCompile(`/(api/)?(notifications?|emails?|sms|webhooks?)(/|$)`),
		purpose:    "messaging",
		threat:     "ssrf,phishing,business-logic",
		risk:       "medium",
		dataType:   "contact-info",
		baseWeight: 0.7,
	},
	{
		keywords:   []string{"settings", "config", "preference", "option"},
		pathRegex:  regexp.MustCompile(`/(api/)?(settings?|configs?|preferences?|options?)(/|$)`),
		purpose:    "configuration",
		threat:     "idor,xss,stored-xss",
		risk:       "medium",
		dataType:   "config",
		baseWeight: 0.6,
	},
	{
		keywords:   []string{"session", "activity", "log", "audit"},
		pathRegex:  regexp.MustCompile(`/(api/)?(sessions?|activities?|logs?|audits?)(/|$)`),
		purpose:    "audit",
		threat:     "information-disclosure,access-control",
		risk:       "low",
		dataType:   "audit-log",
		baseWeight: 0.4,
	},
}

var methodRisk = map[string]float64{
	"GET":    0.3,
	"POST":   0.5,
	"PUT":    0.8,
	"PATCH":  0.8,
	"DELETE": 0.9,
}

var methodRiskLabel = map[string]string{
	"GET":    "low",
	"POST":   "medium",
	"PUT":    "high",
	"PATCH":  "high",
	"DELETE": "high",
}

func ClassifyEndpoint(path, method string) EndpointModel {
	pathLower := strings.ToLower(path)

	type matchResult struct {
		index          int
		score          float64
		keywordMatches int
		regexMatch     bool
	}

	var matches []matchResult

	for i, c := range purposeClassifiers {
		score := 0.0
		keywordMatches := 0
		regexMatch := false

		for _, kw := range c.keywords {
			if strings.Contains(pathLower, kw) {
				score += c.baseWeight
				keywordMatches++
			}
		}

		if c.pathRegex.MatchString(pathLower) {
			score += c.baseWeight * 2.0
			regexMatch = true
		}

		pathSegments := strings.Split(strings.Trim(pathLower, "/"), "/")
		segmentBonus := 0.0
		for _, seg := range pathSegments {
			for _, kw := range c.keywords {
				if seg == kw {
					segmentBonus += c.baseWeight * 0.5
				}
			}
		}
		score += segmentBonus

		if keywordMatches > 0 || regexMatch {
			matches = append(matches, matchResult{
				index:          i,
				score:          score,
				keywordMatches: keywordMatches,
				regexMatch:     regexMatch,
			})
		}
	}

	if len(matches) > 0 {
		best := matches[0]
		for _, m := range matches[1:] {
			if m.score > best.score {
				best = m
			}
		}

		c := purposeClassifiers[best.index]
		totalPossible := float64(len(c.keywords)) * c.baseWeight * 1.5
		if totalPossible == 0 {
			totalPossible = 1
		}
		confidence := math.Min(1.0, best.score/totalPossible)
		if best.regexMatch {
			confidence = math.Min(1.0, confidence+0.2)
		}
		if best.keywordMatches >= 2 {
			confidence = math.Min(1.0, confidence+0.1)
		}

		authReq := strings.Contains(pathLower, "login") || strings.Contains(pathLower, "auth")
		return EndpointModel{
			Path:         path,
			Method:       method,
			Purpose:      c.purpose,
			Threat:       c.threat,
			RiskLevel:    c.risk,
			DataType:     c.dataType,
			AuthRequired: authReq,
			Confidence:   confidence,
		}
	}

	mRisk := methodRiskLabel[method]
	if mRisk == "" {
		mRisk = "medium"
	}
	mScore := methodRisk[method]
	if mScore == 0 {
		mScore = 0.5
	}

	return EndpointModel{
		Path:         path,
		Method:       method,
		Purpose:      "general",
		Threat:       "unknown",
		RiskLevel:    mRisk,
		DataType:     "unknown",
		AuthRequired: true,
		Confidence:   mScore,
	}
}

func BuildFromReconnData(endpoints []string, techStack []string, client *llm.Client) (*AppModel, error) {
	model := &AppModel{
		Endpoints:   make([]EndpointModel, 0, len(endpoints)),
		TechStack:   techStack,
		GeneratedAt: time.Now(),
	}

	for _, ep := range endpoints {
		method := "GET"
		parts := strings.SplitN(ep, " ", 2)
		if len(parts) == 2 {
			method = parts[0]
			ep = parts[1]
		}

		classified := ClassifyEndpoint(ep, method)
		model.Endpoints = append(model.Endpoints, classified)
	}

	return model, nil
}

func (m *AppModel) HighRiskEndpoints() []EndpointModel {
	var high []EndpointModel
	for _, ep := range m.Endpoints {
		if ep.RiskLevel == "critical" || ep.RiskLevel == "high" {
			high = append(high, ep)
		}
	}
	return high
}

func (m *AppModel) AttackPriorities() []string {
	var priorities []string

	criticalCount := 0
	highCount := 0

	for _, ep := range m.Endpoints {
		switch ep.RiskLevel {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
	}

	if criticalCount > 0 {
		priorities = append(priorities, "Priority 1: Test financial/admin endpoints for IDOR, auth bypass, mass assignment")
	}
	if highCount > 0 {
		priorities = append(priorities, "Priority 2: Test file upload endpoints for RCE, XSS")
		priorities = append(priorities, "Priority 3: Test API endpoints for mass assignment, missing auth")
	}
	priorities = append(priorities, "Priority 4: Test user content endpoints for XSS, SSTI, injection")

	return priorities
}

func (m *AppModel) SuggestPayloads() map[string][]string {
	suggestions := make(map[string][]string)

	for _, ep := range m.Endpoints {
		switch ep.Purpose {
		case "financial":
			suggestions["idor"] = append(suggestions["idor"], "test different user IDs in same session", "test sequential ID enumeration")
			suggestions["mass-assignment"] = append(suggestions["mass-assignment"], "submit role=admin parameter", "submit _override flags")
		case "admin-panel":
			suggestions["auth-bypass"] = append(suggestions["auth-bypass"], "test default creds", "test session hijacking", "test privilege escalation")
		case "file-handling":
			suggestions["rce"] = append(suggestions["rce"], "upload webshell", "upload polyglot", "test path traversal in filename")
			suggestions["xss"] = append(suggestions["xss"], "upload SVG with script", "upload HTML with iframe")
		case "user-content":
			suggestions["xss"] = append(suggestions["xss"], "<script>alert(1)</script>", "<img src=x onerror=alert(1)>")
			suggestions["ssti"] = append(suggestions["ssti"], "{{7*7}}", "${7*7}", "<%=7*7%>")
		case "authentication":
			suggestions["auth-bypass"] = append(suggestions["auth-bypass"], "SQLi login bypass", "JWT tampering", "session fixation")
			suggestions["credential-stuffing"] = append(suggestions["credential-stuffing"], "test known creds from breaches")
		case "api-endpoint":
			suggestions["mass-assignment"] = append(suggestions["mass-assignment"], "submit extra fields", "submit admin/user role fields")
			suggestions["idor"] = append(suggestions["idor"], "test accessing other users resources", "test ID enumeration")
		}
	}

	return suggestions
}

func (m *AppModel) ExcludedPaths() []string {
	var excluded []string
	for _, ep := range m.Endpoints {
		if ep.Purpose == "audit" || ep.Purpose == "session" {
			excluded = append(excluded, ep.Path)
		}
	}
	return excluded
}

func (m *AppModel) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("App Model for %s\n", m.Target))
	sb.WriteString(fmt.Sprintf("Tech stack: %s\n", strings.Join(m.TechStack, ", ")))
	sb.WriteString(fmt.Sprintf("Endpoints modeled: %d\n", len(m.Endpoints)))

	high := m.HighRiskEndpoints()
	if len(high) > 0 {
		sb.WriteString(fmt.Sprintf("\nHigh-risk endpoints (%d):\n", len(high)))
		for _, ep := range high {
			sb.WriteString(fmt.Sprintf("  [%s] %s | %s | %s | auth:%v | confidence:%.2f\n", ep.Method, ep.Path, ep.Purpose, ep.Threat, ep.AuthRequired, ep.Confidence))
		}
	}

	priorities := m.AttackPriorities()
	if len(priorities) > 0 {
		sb.WriteString("\nAttack priorities:\n")
		for _, p := range priorities {
			sb.WriteString(fmt.Sprintf("  %s\n", p))
		}
	}

	return sb.String()
}

func ModelToJSON(m *AppModel) string {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

func ParseClassification(resp string, path, method string) (EndpointModel, error) {
	var result struct {
		Purpose      string  `json:"purpose"`
		Threat       string  `json:"threat"`
		RiskLevel    string  `json:"risk_level"`
		DataType     string  `json:"data_type"`
		AuthRequired bool    `json:"auth_required"`
		Confidence   float64 `json:"confidence"`
	}
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		return EndpointModel{}, err
	}
	if result.Confidence <= 0 {
		result.Confidence = 0.5
	}
	return EndpointModel{
		Path:         path,
		Method:       method,
		Purpose:      result.Purpose,
		Threat:       result.Threat,
		RiskLevel:    result.RiskLevel,
		DataType:     result.DataType,
		AuthRequired: result.AuthRequired,
		Confidence:   result.Confidence,
	}, nil
}

type LLMClassifier struct {
	client *llm.Client
}

func NewLLMClassifier(client *llm.Client) *LLMClassifier {
	return &LLMClassifier{client: client}
}

func (c *LLMClassifier) Classify(ctx context.Context, path, method string) (EndpointModel, error) {
	if c.client == nil {
		return ClassifyEndpoint(path, method), nil
	}

	prompt := fmt.Sprintf(`Classify this endpoint: %s %s
Respond with JSON: {"purpose":"...","threat":"...","risk_level":"low|medium|high|critical","data_type":"...","auth_required":true|false,"confidence":0.0-1.0}
Examples:
- POST /api/users -> {"purpose":"user-identity","threat":"mass-assignment,idor","risk_level":"high","data_type":"pii","auth_required":true,"confidence":0.85}
- GET /api/search -> {"purpose":"search","threat":"information-disclosure","risk_level":"medium","data_type":"user-content","auth_required":false,"confidence":0.70}`, method, path)

	messages := []llm.Message{{Role: "user", Content: prompt}}
	resp, err := c.client.Complete(ctx, messages, "")
	if err != nil {
		return ClassifyEndpoint(path, method), err
	}
	return ParseClassification(resp, path, method)
}
