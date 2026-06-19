package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ares/engine/internal/security"
)

type JSAnalysis struct {
	URL          string      `json:"url"`
	Endpoints    []string    `json:"endpoints"`
	APIRoutes    []string    `json:"api_routes"`
	Secrets      []Secret    `json:"secrets"`
	Imports      []string    `json:"imports"`
	FetchCalls   []FetchCall `json:"fetch_calls"`
	AxiosCalls   []string    `json:"axios_calls"`
	XHRCalls     []string    `json:"xhr_calls"`
	GraphQLOps   []string    `json:"graphql_operations"`
	AuthPatterns []string    `json:"auth_patterns"`
	TechStack    []string    `json:"tech_stack"`
	Comments     []string    `json:"interesting_comments"`
}

type Secret struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Line    int    `json:"line"`
	Context string `json:"context"`
}

type FetchCall struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Line   int    `json:"line"`
}

func AnalyzeJS(sourceURL, jsURL string) (*JSAnalysis, error) {
	content, err := fetchURL(jsURL)
	if err != nil {
		content, err = fetchURL(sourceURL)
		if err != nil {
			return nil, fmt.Errorf("fetch JS: %w", err)
		}
	}

	analysis := &JSAnalysis{URL: jsURL}
	analysis.Secrets = findSecrets(content)
	analysis.FetchCalls = findFetchCalls(content)
	analysis.AxiosCalls = findAxiosCalls(content)
	analysis.XHRCalls = findXHRCalls(content)
	analysis.GraphQLOps = findGraphQLOps(content)
	analysis.APIRoutes = extractAPIRoutes(content)
	analysis.Endpoints = extractEndpoints(content)
	analysis.AuthPatterns = findAuthPatterns(content)
	analysis.Imports = findImports(content)
	analysis.Comments = findInterestingComments(content)
	analysis.TechStack = detectTechStack(content)

	return analysis, nil
}

func fetchURL(url string) (string, error) {
	if err := security.ValidateURL(url); err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

var secretPatterns = []struct {
	Type  string
	Regex *regexp.Regexp
}{
	{"AWS Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret", regexp.MustCompile(`(?i)aws_secret_access_key["\s:=]+['"][a-zA-Z0-9/+=]{40}['"]`)},
	{"GitHub Token", regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
	{"GitHub OAuth", regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`)},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/`)},
	{"Stripe Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"Stripe Publishable", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`)},
	{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)["\s:=]+['"][a-zA-Z0-9_-]{20,}['"]`)},
	{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_.-]{20,}`)},
	{"JWT", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{"Basic Auth", regexp.MustCompile(`(?i)authorization:\s*Basic\s+[a-zA-Z0-9+=]{20,}`)},
	{"Password in URL", regexp.MustCompile(`[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+`)},
	{"Database URL", regexp.MustCompile(`(?i)(mysql|postgres|postgresql|mongodb)://[^\s'"]{20,}`)},
	{"Google API", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"SendGrid", regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`)},
	{"Mailgun", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)},
	{"Twilio", regexp.MustCompile(`SK[a-z0-9a-fA-F]{32}`)},
	{"NPM Token", regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)},
}

func findSecrets(content string) []Secret {
	var secrets []Secret
	lines := strings.Split(content, "\n")
	skipPatterns := []string{"example", "test", "placeholder", "dummy", "your_", "foo", "bar", "localhost", "127.0.0.1"}

	for lineNum, line := range lines {
		for _, pat := range secretPatterns {
			matches := pat.Regex.FindAllString(line, -1)
			for _, match := range matches {
				lower := strings.ToLower(match)
				skip := false
				for _, sp := range skipPatterns {
					if strings.Contains(lower, sp) {
						skip = true
						break
					}
				}
				if skip {
					continue
				}
				value := match
				if len(value) > 60 {
					value = value[:60] + "..."
				}
				context := strings.TrimSpace(line)
				if len(context) > 100 {
					context = context[:100] + "..."
				}
				secrets = append(secrets, Secret{
					Type:    pat.Type,
					Value:   value,
					Line:    lineNum + 1,
					Context: context,
				})
			}
		}
	}
	return secrets
}

func findFetchCalls(content string) []FetchCall {
	var calls []FetchCall
	lines := strings.Split(content, "\n")
	fetchRe := regexp.MustCompile(`(?:fetch|axios)\s*\(\s*['"]([^'"]+)['"]`)
	methodRe := regexp.MustCompile(`method:\s*['"](GET|POST|PUT|DELETE|PATCH)['"]`)

	for lineNum, line := range lines {
		matches := fetchRe.FindAllStringSubmatch(line, -1)
		methodMatches := methodRe.FindAllStringSubmatch(line, -1)

		method := "GET"
		for _, m := range methodMatches {
			if len(m) > 1 {
				switch m[1] {
				case "POST":
					method = "POST"
				case "PUT":
					method = "PUT"
				case "DELETE":
					method = "DELETE"
				case "PATCH":
					method = "PATCH"
				}
				break
			}
		}

		for _, match := range matches {
			if len(match) > 1 {
				calls = append(calls, FetchCall{
					URL:    match[1],
					Method: method,
					Line:   lineNum + 1,
				})
			}
		}
	}
	return calls
}

func findAxiosCalls(content string) []string {
	var calls []string
	axiosGet := regexp.MustCompile(`axios\.get\s*\(\s*['"]([^'"]+)['"]`)
	axiosPost := regexp.MustCompile(`axios\.post\s*\(\s*['"]([^'"]+)['"]`)
	axiosPut := regexp.MustCompile(`axios\.put\s*\(\s*['"]([^'"]+)['"]`)
	axiosDel := regexp.MustCompile(`axios\.delete\s*\(\s*['"]([^'"]+)['"]`)

	for _, re := range []*regexp.Regexp{axiosGet, axiosPost, axiosPut, axiosDel} {
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) > 1 && m[1] != "" {
				calls = append(calls, m[1])
			}
		}
	}
	return calls
}

func findXHRCalls(content string) []string {
	var calls []string
	xhr := regexp.MustCompile(`new\s+XMLHttpRequest\(\)[\s\S]{0,200}\.open\s*\(\s*['"](GET|POST|PUT|DELETE)['"]\s*,\s*['"]([^'"]+)['"]`)
	matches := xhr.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) > 2 {
			calls = append(calls, m[2])
		}
	}
	return calls
}

func findGraphQLOps(content string) []string {
	var ops []string
	gqlPattern := regexp.MustCompile(`(?:gql|graphql)\x60([\s\S]*?)\x60`)
	matches := gqlPattern.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) > 1 {
			op := strings.TrimSpace(m[1])
			if op != "" {
				ops = append(ops, op)
			}
		}
	}
	queryKeyword := regexp.MustCompile(`(?i)\b(query|mutation|subscription)\s+\w*`)
	qmatches := queryKeyword.FindAllString(content, -1)
	for _, q := range qmatches {
		ops = append(ops, q)
	}
	return ops
}

func extractAPIRoutes(content string) []string {
	seen := make(map[string]bool)
	var routes []string
	patterns := []string{
		`/api/[a-zA-Z0-9_/-]+`,
		`/v\d+/[a-zA-Z0-9_/-]+`,
		`/rest/[a-zA-Z0-9_/-]+`,
		`/graphql`,
		`/graphql/v1`,
		`/api/v[0-9]/[a-zA-Z0-9_/-]+`,
		`/[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*`,
		`/(?:users|auth|login|register|admin|api|dashboard|profile|settings|account)/[a-zA-Z0-9_/-]*`,
	}
	for _, pat := range patterns {
		re := regexp.MustCompile(pat)
		matches := re.FindAllString(content, -1)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				routes = append(routes, m)
			}
		}
	}
	return routes
}

func extractEndpoints(content string) []string {
	seen := make(map[string]bool)
	var endpoints []string
	urlPattern := regexp.MustCompile(`['"](https?://[^'"]+)['"]`)
	matches := urlPattern.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) > 1 && m[1] != "" {
			url := m[1]
			if !seen[url] && len(url) > 10 && len(url) < 500 {
				seen[url] = true
				endpoints = append(endpoints, url)
			}
		}
	}
	return endpoints
}

var authPatterns = []string{
	"Authorization", "Bearer", "jwt", "token", "session", "cookie",
	"csrf", "xsrf", "cors", "Credentials", "withCredentials",
	"Access-Control-Allow-Credentials",
}

func findAuthPatterns(content string) []string {
	var found []string
	seen := make(map[string]bool)
	for _, p := range authPatterns {
		if strings.Contains(content, p) && !seen[p] {
			seen[p] = true
			found = append(found, p)
		}
	}
	return found
}

func findImports(content string) []string {
	var imports []string
	seen := make(map[string]bool)
	importPatterns := []string{
		`import\s+.*?from\s+['"]([^'"]+)['"]`,
		`require\s*\(\s*['"]([^'"]+)['"]\s*\)`,
		`const\s+\w+\s+=\s+require\s*\(\s*['"]([^'"]+)['"]\s*\)`,
	}
	for _, pat := range importPatterns {
		re := regexp.MustCompile(pat)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) > 1 && m[1] != "" {
				imp := m[1]
				if !seen[imp] && !strings.HasPrefix(imp, ".") && !strings.HasPrefix(imp, "/") {
					seen[imp] = true
					imports = append(imports, imp)
				}
			}
		}
	}
	return imports
}

var interestingCommentPatterns = []string{
	"TODO", "FIXME", "HACK", "XXX", "BUG", "NOTE", "IMPORTANT",
	"ADMIN", "DEBUG", "console.log", "debugger", "localhost",
	"127.0.0.1", "baseurl", "api_url", "apiUrl", "endpoint",
	"mock", "fake", "test", "dev",
}

func findInterestingComments(content string) []string {
	var comments []string
	seen := make(map[string]bool)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		for _, pat := range interestingCommentPatterns {
			if strings.Contains(line, pat) && (strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*")) {
				if !seen[line] && len(line) > 3 {
					seen[line] = true
					comment := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "//"), "/*"))
					if len(comment) > 3 && len(comment) < 200 {
						comments = append(comments, comment)
					}
				}
			}
		}
	}
	return comments
}

func detectTechStack(content string) []string {
	indicators := map[string][]string{
		"React":      {"react", "useState", "useEffect", "useCallback", "useMemo", "createElement", "jsx", "ReactDOM"},
		"Vue":        {"vue", "vue-router", "pinia", "composition-api", "setup(", "ref(", "reactive(", "defineComponent"},
		"Angular":    {"@angular", "NgModule", "HttpClient", "RxJS", "BehaviorSubject", "Observable"},
		"jQuery":     {"jquery", "$('#", "$.ajax", "$.post", "$.get", "jQuery."},
		"Next.js":    {"next/router", "next/link", "getServerSideProps", "getStaticProps", "__NEXT_DATA__"},
		"Nuxt.js":    {"nuxt", "$nuxt", "asyncData", "fetch("},
		"Svelte":     {"svelte", "$:", "onMount", "onDestroy", "createEventDispatcher"},
		"Ember":      {"ember", "Ember.", "Route", "Controller", "Component"},
		"Node.js":    {"require(", "exports.", "module.exports", "process.env", "http.createServer"},
		"Express":    {"express", "app.get", "app.post", "router.", "middleware"},
		"FastAPI":    {"fastapi", "uvicorn", "@app.route", "async def", "Pydantic"},
		"Django":     {"django", "from django", "views.", "urls.", "models."},
		"Flask":      {"flask", "Flask(", "render_template", "request.", "@app.route"},
		"Rails":      {"Rails", "ActiveRecord", "ApplicationController", "before_action"},
		"Laravel":    {"laravel", "Route::", "App\\", "Illuminate\\"},
		"Spring":     {"spring", "org.springframework", "@Controller", "@RestController", "RequestMapping"},
		"ASP.NET":    {"asp.net", "System.Web", "Controller", "RouteConfig"},
		"WordPress":  {"wordpress", "wp-content", "the_content", "add_action"},
		"Drupal":     {"drupal", "drupal_add_", "hook_", "Drupal."},
		"Stripe":     {"stripe", "Stripe(", "loadStripe", "Elements", "PaymentElement"},
		"Firebase":   {"firebase", "initializeApp", "getAuth", "Firestore"},
		"Auth0":      {"auth0", "createAuth0Client", "Auth0Provider"},
		"AWS SDK":    {"aws-sdk", "AWS.", "S3", "DynamoDB", "Lambda"},
		"GraphQL":    {"graphql", "Apollo", "urql", "@graphql", "useQuery", "useMutation"},
		"Redux":      {"redux", "createStore", "useSelector", "useDispatch", "@redux"},
		"Vuex":       {"vuex", "Store", "mapState", "mapGetters", "mapActions"},
		"Axios":      {"axios", "axios.get", "axios.post", "axios.create"},
		"TypeScript": {"interface ", ": string", ": number", ": boolean", "<T>", "as "},
	}
	var detected []string
	lower := strings.ToLower(content)
	for framework, keywords := range indicators {
		count := 0
		for _, kw := range keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				count++
			}
		}
		if count >= 1 {
			detected = append(detected, framework)
		}
	}
	return detected
}

func AnalyzeURL(url string) (*JSAnalysis, error) {
	content, err := fetchURL(url)
	if err != nil {
		return nil, err
	}
	analysis := &JSAnalysis{URL: url}
	analysis.Secrets = findSecrets(content)
	analysis.FetchCalls = findFetchCalls(content)
	analysis.GraphQLOps = findGraphQLOps(content)
	analysis.APIRoutes = extractAPIRoutes(content)
	analysis.Endpoints = extractEndpoints(content)
	analysis.AuthPatterns = findAuthPatterns(content)
	analysis.TechStack = detectTechStack(content)
	analysis.Comments = findInterestingComments(content)
	return analysis, nil
}

func RunPageAgent(targetURL string) (*JSAnalysis, error) {
	if err := security.ValidateURL(targetURL); err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	analysis, err := AnalyzeURL(targetURL)
	if err != nil {
		return analysis, nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		return analysis, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	scriptRE := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	for _, m := range scriptRE.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			jsURL := m[1]
			if !strings.HasPrefix(jsURL, "http") {
				if strings.HasPrefix(jsURL, "//") {
					jsURL = "https:" + jsURL
				} else if strings.HasPrefix(jsURL, "/") {
					base := strings.TrimRight(targetURL, "/")
					if idx := strings.Index(base, "://"); idx > 0 {
						if pathIdx := strings.Index(base[idx+3:], "/"); pathIdx > 0 {
							base = base[:idx+3+pathIdx]
						}
					}
					jsURL = base + jsURL
				} else {
					jsURL = strings.TrimRight(targetURL, "/") + "/" + jsURL
				}
			}
			_, err = fetchURL(jsURL)
			if err == nil {
				jsAnalysis, err := AnalyzeJS(targetURL, jsURL)
				if err == nil && jsAnalysis != nil {
					analysis.Endpoints = append(analysis.Endpoints, jsAnalysis.Endpoints...)
					analysis.APIRoutes = append(analysis.APIRoutes, jsAnalysis.APIRoutes...)
					analysis.Secrets = append(analysis.Secrets, jsAnalysis.Secrets...)
					analysis.AuthPatterns = append(analysis.AuthPatterns, jsAnalysis.AuthPatterns...)
				}
			}
		}
	}

	linkRE := regexp.MustCompile(`<a[^>]+href=["']([^"']+)["']`)
	linkMatches := linkRE.FindAllStringSubmatch(content, -1)
	for _, m := range linkMatches {
		if len(m) > 1 {
			href := m[1]
			if strings.HasPrefix(href, "/") {
				base := strings.TrimRight(targetURL, "/")
				if idx := strings.Index(base, "://"); idx > 0 {
					if pathIdx := strings.Index(base[idx+3:], "/"); pathIdx > 0 {
						base = base[:idx+3+pathIdx]
					}
				}
				analysis.Endpoints = append(analysis.Endpoints, base+href)
			}
		}
	}

	return analysis, nil
}

func (a *JSAnalysis) Summary() string {
	return fmt.Sprintf("JS Analysis: %d endpoints, %d secrets, %d API routes, %d GraphQL ops, frameworks: %v",
		len(a.Endpoints), len(a.Secrets), len(a.APIRoutes), len(a.GraphQLOps), a.TechStack)
}

func ParseGraphQLSchema(schemaJSON string) (*GraphQLSchema, error) {
	var schema GraphQLSchema
	if err := json.Unmarshal([]byte(schemaJSON), &schema); err != nil {
		return nil, err
	}
	return &schema, nil
}

type GraphQLSchema struct {
	QueryType        *GQLType           `json:"queryType"`
	MutationType     *GQLType           `json:"mutationType"`
	SubscriptionType *GQLType           `json:"subscriptionType"`
	Types            map[string]GQLType `json:"types"`
	Directives       []GQLDirective     `json:"directives"`
}

type GQLType struct {
	Name   string              `json:"name"`
	Fields map[string]GQLField `json:"fields"`
	Kind   string              `json:"kind"`
}

type GQLField struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Args         []GQLArg `json:"args"`
	IsDeprecated bool     `json:"isDeprecated"`
}

type GQLArg struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	DefaultValue string `json:"defaultValue"`
}

type GQLDirective struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Locations   []string `json:"locations"`
}

func FetchGraphQLSchema(url string, headers map[string]string) (*GraphQLSchema, error) {
	if err := security.ValidateURL(url); err != nil {
		return nil, fmt.Errorf("URL validation failed: %w", err)
	}
	query := `{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name type args { name type } } } } }","variables":{}}`
	req, _ := http.NewRequest("POST", url, strings.NewReader(query))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch GraphQL schema: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fetch GraphQL schema: %w", err)
	}

	var gqlResp struct {
		Data struct {
			Schema GraphQLSchema `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &gqlResp); err != nil {
		return nil, fmt.Errorf("parse GraphQL schema: %w", err)
	}
	return &gqlResp.Data.Schema, nil
}

func FuzzGraphQLFields(url string, schema *GraphQLSchema) []string {
	var fuzzedQueries []string
	if schema.QueryType != nil && schema.QueryType.Fields != nil {
		for fieldName, field := range schema.QueryType.Fields {
			varArgs := ""
			if len(field.Args) > 0 {
				varArgList := []string{}
				maxArgs := 2
				if len(field.Args) < maxArgs {
					maxArgs = len(field.Args)
				}
				for _, arg := range field.Args[:maxArgs] {
					varArgList = append(varArgList, fmt.Sprintf("%s: $%s", arg.Name, arg.Name))
				}
				varArgs = "(" + strings.Join(varArgList, ", ") + ")"
			}
			fuzzedQueries = append(fuzzedQueries, fmt.Sprintf("query { %s%s { %s } }", fieldName, varArgs, field.Type))
		}
	}
	return fuzzedQueries
}

func DetectGraphQLIntrospection(url string) bool {
	if err := security.ValidateURL(url); err != nil {
		return false
	}
	query := `{"query":"{ __typename }","variables":{}}`
	req, _ := http.NewRequest("POST", url, strings.NewReader(query))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "__typename") || strings.Contains(string(data), "data")
}

func BuildGraphQLTestSuite(url string, schema *GraphQLSchema) []string {
	var tests []string
	if schema.QueryType != nil && schema.QueryType.Fields != nil {
		for name, field := range schema.QueryType.Fields {
			tests = append(tests, fmt.Sprintf("query_%s", name))
			for _, arg := range field.Args {
				if strings.Contains(strings.ToLower(arg.Name), "id") {
					tests = append(tests, fmt.Sprintf("query_%s_id_manipulation", name))
				}
			}
		}
	}
	if schema.MutationType != nil {
		tests = append(tests, "mutation_auth_bypass")
		tests = append(tests, "mutation_null_injection")
	}
	tests = append(tests, "graphql_depth_limit_bypass")
	tests = append(tests, "graphql_alias_bypass")
	tests = append(tests, "graphql_introspection_disabled")
	return tests
}
