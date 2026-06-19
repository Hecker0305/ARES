package coderemediation

import (
	"strings"
	"testing"
)

func TestFixGenerator(t *testing.T) {
	fg := NewFixGenerator()

	tests := []struct {
		name     string
		req      FixRequest
		language string
		findType string
	}{
		{
			name: "SQL Injection Go",
			req: FixRequest{
				FindingType: "sqli",
				Language:    "go",
				Context:     `db.Query("SELECT * FROM users WHERE id = " + id)`,
				FilePath:    "main.go",
			},
			language: "go",
			findType: "sqli",
		},
		{
			name: "XSS JavaScript",
			req: FixRequest{
				FindingType: "xss",
				Language:    "javascript",
				Context:     `element.innerHTML = userInput`,
				FilePath:    "app.js",
			},
			language: "javascript",
			findType: "xss",
		},
		{
			name: "CSRF Python",
			req: FixRequest{
				FindingType: "csrf",
				Language:    "python",
				Context:     `@app.route('/submit', methods=['POST'])\ndef submit():`,
				FilePath:    "app.py",
			},
			language: "python",
			findType: "csrf",
		},
		{
			name: "SSRF Java",
			req: FixRequest{
				FindingType: "ssrf",
				Language:    "java",
				Context:     `URL url = new URL(userInput);\nHttpURLConnection conn = (HttpURLConnection) url.openConnection();`,
				FilePath:    "Main.java",
			},
			language: "java",
			findType: "ssrf",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fix := fg.GenerateFix(test.req)

			if fix == nil {
				t.Fatal("Fix should not be nil")
			}

			if fix.Language != test.language {
				t.Errorf("Expected language %s, got %s", test.language, fix.Language)
			}

			if !strings.Contains(fix.Diff, "+") || !strings.Contains(fix.Diff, "-") {
				t.Errorf("Diff should contain both + and - lines, got: %s", fix.Diff)
			}

			if fix.Description == "" {
				t.Error("Description should not be empty")
			}
		})
	}
}

func TestSQLInjectionFixes(t *testing.T) {
	fg := NewFixGenerator()

	languages := []string{"go", "python", "javascript", "java", "csharp", "rust"}

	for _, lang := range languages {
		t.Run(lang, func(t *testing.T) {
			req := FixRequest{
				FindingType: "sqli",
				Language:    lang,
				Context:     "original vulnerable code",
				FilePath:    "test." + lang,
			}

			fix := fg.GenerateFix(req)

			if fix == nil {
				t.Fatalf("Fix should not be nil for %s", lang)
			}

			// Check that the fix mentions parameterized queries
			if lang == "go" && !strings.Contains(fix.FixedCode, "?") {
				t.Errorf("Go fix should use ? placeholders, got: %s", fix.FixedCode)
			}

			if lang == "python" && !strings.Contains(fix.FixedCode, "%s") {
				t.Errorf("Python fix should use %%s placeholders, got: %s", fix.FixedCode)
			}

			if (lang == "javascript" || lang == "typescript") && !strings.Contains(fix.FixedCode, "?") {
				t.Errorf("JavaScript/TypeScript fix should use ? placeholders, got: %s", fix.FixedCode)
			}
		})
	}
}

func TestXSSFixes(t *testing.T) {
	fg := NewFixGenerator()

	req := FixRequest{
		FindingType: "xss",
		Language:    "go",
		Context:     `w.Write([]byte(userInput))`,
		FilePath:    "main.go",
	}

	fix := fg.GenerateFix(req)

	if fix == nil {
		t.Fatal("Fix should not be nil")
	}

	if !strings.Contains(fix.FixedCode, "html.EscapeString") {
		t.Errorf("Go XSS fix should use html.EscapeString, got: %s", fix.FixedCode)
	}

	if !strings.Contains(fix.Description, "output encoding") {
		t.Errorf("Description should mention output encoding, got: %s", fix.Description)
	}
}

func TestCSRFProtection(t *testing.T) {
	fg := NewFixGenerator()

	req := FixRequest{
		FindingType: "csrf",
		Language:    "go",
		Context:     `r.HandleFunc("/api/submit", submitHandler)`,
		FilePath:    "main.go",
	}

	fix := fg.GenerateFix(req)

	if fix == nil {
		t.Fatal("Fix should not be nil")
	}

	if !strings.Contains(fix.FixedCode, "csrf.Protect") {
		t.Errorf("Go CSRF fix should use csrf.Protect, got: %s", fix.FixedCode)
	}
}

func TestSSRFProtection(t *testing.T) {
	fg := NewFixGenerator()

	req := FixRequest{
		FindingType: "ssrf",
		Language:    "go",
		Context:     `resp, err := http.Get(userURL)`,
		FilePath:    "main.go",
	}

	fix := fg.GenerateFix(req)

	if fix == nil {
		t.Fatal("Fix should not be nil")
	}

	if !strings.Contains(fix.FixedCode, "isInternalIP") {
		t.Errorf("Go SSRF fix should validate IP addresses, got: %s", fix.FixedCode)
	}
}

func TestIDORProtection(t *testing.T) {
	fg := NewFixGenerator()

	req := FixRequest{
		FindingType: "idor",
		Language:    "go",
		Context:     `func GetDocument(w http.ResponseWriter, r *http.Request) {\n    docID := r.URL.Query().Get("id")\n    doc := db.GetDocument(docID)\n    json.NewEncoder(w).Encode(doc)\n}`,
		FilePath:    "main.go",
	}

	fix := fg.GenerateFix(req)

	if fix == nil {
		t.Fatal("Fix should not be nil")
	}

	if !strings.Contains(fix.FixedCode, "getUserID") {
		t.Errorf("Go IDOR fix should check user ownership, got: %s", fix.FixedCode)
	}
}

func TestRCEProtection(t *testing.T) {
	fg := NewFixGenerator()

	req := FixRequest{
		FindingType: "rce",
		Language:    "go",
		Context:     `cmd := exec.Command("sh", "-c", userInput)`,
		FilePath:    "main.go",
	}

	fix := fg.GenerateFix(req)

	if fix == nil {
		t.Fatal("Fix should not be nil")
	}

	if !strings.Contains(fix.FixedCode, "allowed") || !strings.Contains(fix.FixedCode, "metacharacters") {
		t.Errorf("Go RCE fix should validate commands, got: %s", fix.FixedCode)
	}
}

func TestGenericFix(t *testing.T) {
	fg := NewFixGenerator()

	req := FixRequest{
		FindingType: "unknown-vulnerability",
		Language:    "go",
		Context:     "some code",
		FilePath:    "main.go",
	}

	fix := fg.GenerateFix(req)

	if fix == nil {
		t.Fatal("Fix should not be nil")
	}

	if !strings.Contains(fix.Description, "manual review recommended") {
		t.Errorf("Generic fix should recommend manual review, got: %s", fix.Description)
	}
}

func TestGenerateDiff(t *testing.T) {
	original := "line1\nline2\nline3"
	fixed := "line1\nline2-fixed\nline3"

	diff := generateDiff(original, fixed)

	if !strings.Contains(diff, "- line2") {
		t.Errorf("Diff should contain removed line, got: %s", diff)
	}

	if !strings.Contains(diff, "+ line2-fixed") {
		t.Errorf("Diff should contain added line, got: %s", diff)
	}
}

func TestSupportedLanguages(t *testing.T) {
	fg := NewFixGenerator()

	supported := []string{"go", "python", "javascript", "typescript", "java", "csharp", "rust"}

	for _, lang := range supported {
		if !fg.supportedLanguages[lang] {
			t.Errorf("Language %s should be supported", lang)
		}
	}

	// Test unsupported language
	unsupported := "cobol"
	if fg.supportedLanguages[unsupported] {
		t.Errorf("Language %s should not be supported", unsupported)
	}
}

func TestFilePathDetection(t *testing.T) {
	fg := NewFixGenerator()

	req := FixRequest{
		FindingType: "sqli",
		Language:    "go",
		Context:     "test code",
		FilePath:    "", // Empty should auto-generate
	}

	fix := fg.GenerateFix(req)

	if fix == nil {
		t.Fatal("Fix should not be nil")
	}

	if fix.FilePath != "fix_sqli.go" {
		t.Errorf("Expected auto-generated filename 'fix_sqli.go', got: %s", fix.FilePath)
	}
}
