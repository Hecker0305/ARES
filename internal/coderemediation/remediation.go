package coderemediation

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/ares/engine/internal/llm"
)

type FixSnippet struct {
	Language     string `json:"language"`
	OriginalCode string `json:"original_code"`
	FixedCode    string `json:"fixed_code"`
	Diff         string `json:"diff"`
	FilePath     string `json:"file_path"`
	Description  string `json:"description"`
}

type FixGenerator struct {
	supportedLanguages map[string]bool
	llmClient          *llm.Client
}

func NewFixGenerator() *FixGenerator {
	return &FixGenerator{
		supportedLanguages: map[string]bool{
			"go": true, "python": true, "javascript": true,
			"typescript": true, "java": true, "csharp": true,
			"rust": true,
		},
	}
}

func NewFixGeneratorWithLLM(client *llm.Client) *FixGenerator {
	return &FixGenerator{
		supportedLanguages: map[string]bool{
			"go": true, "python": true, "javascript": true,
			"typescript": true, "java": true, "csharp": true,
			"rust": true,
		},
		llmClient: client,
	}
}

func (fg *FixGenerator) SetLLMClient(client *llm.Client) {
	fg.llmClient = client
}

type FixRequest struct {
	FindingType string
	Language    string
	Context     string
	FilePath    string
}

func (fg *FixGenerator) GenerateFix(req FixRequest) *FixSnippet {
	findingType := strings.ToLower(req.FindingType)
	lang := strings.ToLower(req.Language)

	switch findingType {
	case "sqli", "sql-injection", "sql_injection":
		return fg.sqliFix(lang, req)
	case "xss", "cross-site-scripting", "cross_site_scripting":
		return fg.xssFix(lang, req)
	case "csrf", "cross-site-request-forgery", "cross_site_request_forgery":
		return fg.csrfFix(lang, req)
	case "ssrf", "server-side-request-forgery", "server_side_request_forgery":
		return fg.ssrfFix(lang, req)
	case "idor", "insecure-direct-object-reference", "insecure_direct_object_reference":
		return fg.idorFix(lang, req)
	case "rce", "remote-code-execution", "remote_code_execution":
		return fg.rceFix(lang, req)
	default:
		return fg.genericFix(lang, req)
	}
}

func (fg *FixGenerator) sqliFix(lang string, req FixRequest) *FixSnippet {
	desc := "Replace string concatenation in SQL queries with parameterized queries to prevent SQL injection."

	filePath := req.FilePath
	if filePath == "" {
		filePath = "fix_sqli." + lang
	}

	switch lang {
	case "go":
		original := `db.Query("SELECT * FROM users WHERE id = " + id)`
		fixed := `db.Query("SELECT * FROM users WHERE id = ?", id)`
		return &FixSnippet{
			Language: "go", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath, Description: desc + " Use ? placeholders with db.Query().",
		}
	case "python":
		original := `cursor.execute(f"SELECT * FROM users WHERE id = {id}")`
		fixed := `cursor.execute("SELECT * FROM users WHERE id = %s", (id,))`
		return &FixSnippet{
			Language: "python", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath, Description: desc + " Use %%s placeholder with parameter tuple.",
		}
	case "javascript", "typescript":
		original := `connection.query('SELECT * FROM users WHERE id = ' + id)`
		fixed := `connection.query('SELECT * FROM users WHERE id = ?', [id])`
		return &FixSnippet{
			Language: lang, OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath, Description: desc + " Use ? placeholder with parameter array.",
		}
	case "java":
		original := `stmt.executeQuery("SELECT * FROM users WHERE id = " + id)`
		fixed := `pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setString(1, id);
rs = pstmt.executeQuery();`
		return &FixSnippet{
			Language: "java", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath, Description: desc + " Use PreparedStatement with ? placeholders.",
		}
	case "csharp":
		original := `cmd.CommandText = "SELECT * FROM users WHERE id = " + id;`
		fixed := `cmd.CommandText = "SELECT * FROM users WHERE id = @id";
cmd.Parameters.AddWithValue("@id", id);`
		return &FixSnippet{
			Language: "csharp", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath, Description: desc + " Use @named parameters.",
		}
	case "rust":
		original := `sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id))`
		fixed := `sqlx::query("SELECT * FROM users WHERE id = $1", id)`
		return &FixSnippet{
			Language: "rust", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath, Description: desc + " Use $n positional parameters.",
		}
	default:
		return fg.genericFix(lang, req)
	}
}

func (fg *FixGenerator) xssFix(lang string, req FixRequest) *FixSnippet {
	desc := "Apply output encoding to prevent cross-site scripting (XSS)."

	filePath := req.FilePath
	if filePath == "" {
		filePath = "fix_xss." + lang
	}

	switch lang {
	case "go":
		original := `w.Write([]byte(userInput))`
		fixed := `w.Write([]byte(html.EscapeString(userInput)))`
		return &FixSnippet{
			Language: "go", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath, Description: desc + " Use html.EscapeString() for HTML output.",
		}
	case "python":
		original := `return render_template("page.html", content=user_input)`
		fixed := `return render_template("page.html", content=user_input)`
		descDjango := desc + " Use |escape filter (Django) or |e (Jinja2) — both are auto-enabled in modern versions. Ensure autoescaping is on."
		return &FixSnippet{
			Language: "python", OriginalCode: original, FixedCode: fixed,
			Diff:     "No code change needed — ensure template engine has auto-escaping enabled.",
			FilePath: filePath, Description: descDjango,
		}
	case "javascript", "typescript":
		original := `element.innerHTML = userInput`
		fixed := `element.textContent = sanitizeHTML(userInput)`
		return &FixSnippet{
			Language: lang, OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Use textContent instead of innerHTML, or use DOMPurify.sanitize().",
		}
	case "java":
		original := `out.println("<div>" + userInput + "</div>")`
		fixed := `out.println("<div>" + StringEscapeUtils.escapeHtml4(userInput) + "</div>")`
		return &FixSnippet{
			Language: "java", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Use StringEscapeUtils.escapeHtml4() from Apache Commons Text.",
		}
	case "csharp":
		original := `@Html.Raw(userInput)`
		fixed := `@Html.Encode(userInput)`
		return &FixSnippet{
			Language: "csharp", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Use Html.Encode() instead of Html.Raw().",
		}
	default:
		return fg.genericFix(lang, req)
	}
}

func (fg *FixGenerator) csrfFix(lang string, req FixRequest) *FixSnippet {
	desc := "Add CSRF token validation to prevent cross-site request forgery."

	filePath := req.FilePath
	if filePath == "" {
		filePath = "fix_csrf." + lang
	}

	switch lang {
	case "go":
		original := `r.HandleFunc("/api/submit", submitHandler)`
		fixed := `r.HandleFunc("/api/submit", submitHandler).Methods("POST")
r.Use(csrf.Protect([]byte("32-byte-long-auth-key"), csrf.Secure(false)))`
		return &FixSnippet{
			Language: "go", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Use gorilla/csrf middleware to protect routes.",
		}
	case "python":
		original := `@app.route('/submit', methods=['POST'])
def submit():`
		fixed := `@app.route('/submit', methods=['POST'])
@csrf.exempt  // Remove this line to enable CSRF protection
def submit():`
		return &FixSnippet{
			Language: "python", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Flask: ensure CSRFProtect extension is enabled. Django: ensure CSRF middleware is active and @csrf_exempt is removed.",
		}
	case "java":
		original := `// No CSRF protection configured`
		fixed := `http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));`
		return &FixSnippet{
			Language: "java", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Spring Security: enable CSRF protection with CookieCsrfTokenRepository.",
		}
	case "csharp":
		original := `// No CSRF token validation`
		fixed := `services.AddAntiforgery(options => options.HeaderName = "X-CSRF-TOKEN");
// On form: @Html.AntiForgeryToken()`
		return &FixSnippet{
			Language: "csharp", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " ASP.NET Core: add Antiforgery service and include token in forms/AJAX requests.",
		}
	default:
		return fg.genericFix(lang, req)
	}
}

func (fg *FixGenerator) ssrfFix(lang string, req FixRequest) *FixSnippet {
	desc := "Add URL validation to prevent server-side request forgery (SSRF)."

	filePath := req.FilePath
	if filePath == "" {
		filePath = "fix_ssrf." + lang
	}

	switch lang {
	case "go":
		original := `resp, err := http.Get(userURL)`
		fixed := `parsedURL, err := url.Parse(userURL)
if err != nil || isInternalIP(parsedURL) {
    return errors.New("invalid or blocked URL")
}
resp, err := http.Get(parsedURL.String())`
		return &FixSnippet{
			Language: "go", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Validate and block internal IPs, use a URL allowlist.",
		}
	case "python":
		original := `response = requests.get(user_url)`
		fixed := `from urllib.parse import urlparse
parsed = urlparse(user_url)
if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0'] or parsed.hostname.startswith('10.') or parsed.hostname.startswith('192.168.'):
    raise ValueError("Blocked internal URL")
response = requests.get(user_url, timeout=5)`
		return &FixSnippet{
			Language: "python", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Validate URL hostname against blocklist of internal addresses.",
		}
	case "java":
		original := `URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();`
		fixed := `InetAddress addr = InetAddress.getByName(new URL(userInput).getHost());
if (addr.isSiteLocalAddress() || addr.isLoopbackAddress()) {
    throw new SecurityException("Blocked internal URL");
}
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();`
		return &FixSnippet{
			Language: "java", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Check InetAddress.isSiteLocalAddress() and isLoopbackAddress().",
		}
	default:
		return fg.genericFix(lang, req)
	}
}

func (fg *FixGenerator) idorFix(lang string, req FixRequest) *FixSnippet {
	desc := "Add ownership/authorization checks to prevent insecure direct object reference."

	filePath := req.FilePath
	if filePath == "" {
		filePath = "fix_idor." + lang
	}

	switch lang {
	case "go":
		original := `func GetDocument(w http.ResponseWriter, r *http.Request) {
    docID := r.URL.Query().Get("id")
    doc := db.GetDocument(docID)
    json.NewEncoder(w).Encode(doc)
}`
		fixed := `func GetDocument(w http.ResponseWriter, r *http.Request) {
    docID := r.URL.Query().Get("id")
    userID := getUserID(r)
    doc := db.GetDocument(docID)
    if doc.OwnerID != userID && !isAdmin(r) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    json.NewEncoder(w).Encode(doc)
}`
		return &FixSnippet{
			Language: "go", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Verify the authenticated user owns the requested resource.",
		}
	case "python":
		original := `def get_document(request, doc_id):
    doc = Document.objects.get(id=doc_id)
    return JsonResponse(doc.to_dict())`
		fixed := `def get_document(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, owner=request.user)
    return JsonResponse(doc.to_dict())`
		return &FixSnippet{
			Language: "python", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Filter query by the authenticated user to enforce ownership.",
		}
	case "java":
		original := `@GetMapping("/documents/{id}")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id).orElseThrow();
}`
		fixed := `@GetMapping("/documents/{id}")
public Document getDocument(@PathVariable Long id, Authentication auth) {
    Document doc = documentRepository.findById(id).orElseThrow();
    if (!doc.getOwner().equals(auth.getName()) && !auth.getAuthorities().contains(ROLE_ADMIN)) {
        throw new AccessDeniedException("Forbidden");
    }
    return doc;
}`
		return &FixSnippet{
			Language: "java", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Check ownership against the authenticated principal.",
		}
	default:
		return fg.genericFix(lang, req)
	}
}

var shellMetaPattern = regexp.MustCompile(`[$|;&` + "`" + `'"\n\r(){}<>!]`)

var safeCommandAllowlist = map[string]bool{
	"ls": true, "cat": true, "grep": true, "find": true,
	"echo": true, "head": true, "tail": true, "wc": true,
	"sort": true, "uniq": true, "cut": true, "sed": true,
	"stat": true, "date": true, "whoami": true, "id": true,
	"uname": true, "hostname": true, "pwd": true,
}

func isShellSafe(input string) bool {
	if shellMetaPattern.MatchString(input) {
		return false
	}
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return false
	}
	return safeCommandAllowlist[parts[0]]
}

func (fg *FixGenerator) rceFix(lang string, req FixRequest) *FixSnippet {
	desc := "Add input validation to prevent remote code execution."

	filePath := req.FilePath
	if filePath == "" {
		filePath = "fix_rce." + lang
	}

	switch lang {
	case "go":
		original := `cmd := exec.Command("sh", "-c", userInput)`
		fixed := `allowed := map[string]bool{"ls": true, "cat": true, "grep": true}
parts := strings.Fields(userInput)
if len(parts) == 0 || !allowed[parts[0]] {
    return errors.New("command not allowed")
}
for _, p := range parts {
    if strings.ContainsAny(p, "$|;&` + "`" + `'\"\\n\\r(){}<>!") {
        return errors.New("shell metacharacters not allowed")
    }
}
cmd := exec.Command(parts[0], parts[1:]...)`
		return &FixSnippet{
			Language: "go", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Use exec.Command with argument slice (no shell), command allowlist, and shell metacharacter rejection. Prevents all injection vectors including $(), ;, |, backticks.",
		}
	case "python":
		original := `result = subprocess.run(user_input, shell=True)`
		fixed := `import shlex
safe_args = shlex.split(user_input)
result = subprocess.run(safe_args, shell=False, check=True)`
		return &FixSnippet{
			Language: "python", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Use shell=False with shlex.split() to prevent shell injection.",
		}
	case "java":
		original := `Runtime.getRuntime().exec(userInput)`
		fixed := `ProcessBuilder pb = new ProcessBuilder(safeCommandList);
pb.redirectErrorStream(true);
Process p = pb.start();`
		return &FixSnippet{
			Language: "java", OriginalCode: original, FixedCode: fixed,
			Diff: generateDiff(original, fixed), FilePath: filePath,
			Description: desc + " Use ProcessBuilder with command list instead of Runtime.exec() with user input.",
		}
	default:
		return fg.genericFix(lang, req)
	}
}

func (fg *FixGenerator) genericFix(lang string, req FixRequest) *FixSnippet {
	if fg.llmClient != nil {
		if llmFix := fg.generateLLMFix(req); llmFix != nil {
			return llmFix
		}
	}

	return &FixSnippet{
		Language:     lang,
		OriginalCode: req.Context,
		FixedCode:    req.Context + "\n// TODO: Review and fix " + req.FindingType + " vulnerability in this code",
		Diff:         "Code review needed for " + req.FindingType + " vulnerability",
		FilePath:     req.FilePath,
		Description:  fmt.Sprintf("Generic fix needed for %s — manual review recommended.", req.FindingType),
	}
}

var secretPatterns = []struct {
	pattern *regexp.Regexp
	replace string
}{
	{regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|token|auth[_-]?token)\s*[:=]\s*["'][^"']+["']`), `$1: "[REDACTED]"`},
	{regexp.MustCompile(`(?i)(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16,}`), "[REDACTED_AWS_KEY]"},
	{regexp.MustCompile(`-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----`), "[REDACTED_PRIVATE_KEY]"},
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}`), "[REDACTED_GITHUB_TOKEN]"},
}

func redactSecrets(code string) string {
	for _, p := range secretPatterns {
		code = p.pattern.ReplaceAllString(code, p.replace)
	}
	return code
}

func (fg *FixGenerator) generateLLMFix(req FixRequest) *FixSnippet {
	ctx := context.Background()

	safeCode := redactSecrets(req.Context)

	prompt := fmt.Sprintf(`You are a security expert. Fix the following %s vulnerability in %s code.

Vulnerability Type: %s
Original Code:
%s

Provide ONLY the fixed code, no explanations. The fix should:
1. Address the security vulnerability
2. Follow best practices for the language
3. Be production-ready

Return the fixed code only.`, req.FindingType, req.Language, req.FindingType, safeCode)

	messages := []llm.Message{
		{Role: "system", Content: "You are a senior security engineer specializing in code remediation. Provide only the fixed code."},
		{Role: "user", Content: prompt},
	}

	fixedCode, err := fg.llmClient.Complete(ctx, messages, "")
	if err != nil {
		return nil
	}

	fixedCode = strings.TrimSpace(fixedCode)
	fixedCode = strings.TrimPrefix(fixedCode, "```"+req.Language)
	fixedCode = strings.TrimPrefix(fixedCode, "```")
	fixedCode = strings.TrimSuffix(fixedCode, "```")
	fixedCode = strings.TrimSpace(fixedCode)

	if fixedCode == "" {
		return nil
	}

	return &FixSnippet{
		Language:     req.Language,
		OriginalCode: req.Context,
		FixedCode:    fixedCode,
		Diff:         generateDiff(req.Context, fixedCode),
		FilePath:     req.FilePath,
		Description:  fmt.Sprintf("LLM-generated fix for %s vulnerability in %s", req.FindingType, req.Language),
	}
}

func generateDiff(original, fixed string) string {
	oLines := strings.Split(original, "\n")
	fLines := strings.Split(fixed, "\n")
	var diff strings.Builder
	for _, l := range oLines {
		diff.WriteString("- " + l + "\n")
	}
	for _, l := range fLines {
		diff.WriteString("+ " + l + "\n")
	}
	return diff.String()
}
