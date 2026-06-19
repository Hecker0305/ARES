package cwemap

import (
	"testing"
)

func TestLookup(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantID      string
		wantName    string
		wantURL     string
		wantDefault bool
	}{
		{
			name:   "SQL injection",
			input:  "sqli",
			wantID: "CWE-89",
		},
		{
			name:   "XSS",
			input:  "xss",
			wantID: "CWE-79",
		},
		{
			name:   "SSRF",
			input:  "ssrf",
			wantID: "CWE-918",
		},
		{
			name:   "RCE",
			input:  "rce",
			wantID: "CWE-94",
		},
		{
			name:   "IDOR",
			input:  "idor",
			wantID: "CWE-639",
		},
		{
			name:   "CSRF",
			input:  "csrf",
			wantID: "CWE-352",
		},
		{
			name:   "XXE",
			input:  "xxe",
			wantID: "CWE-611",
		},
		{
			name:   "NoSQLi",
			input:  "nosqli",
			wantID: "CWE-943",
		},
		{
			name:   "LFI",
			input:  "lfi",
			wantID: "CWE-98",
		},
		{
			name:   "RFI",
			input:  "rfi",
			wantID: "CWE-98",
		},
		{
			name:   "SSTI",
			input:  "ssti",
			wantID: "CWE-94",
		},
		{
			name:   "Deserialization",
			input:  "deserial",
			wantID: "CWE-502",
		},
		{
			name:   "Path traversal",
			input:  "traversal",
			wantID: "CWE-22",
		},
		{
			name:   "OAuth",
			input:  "oauth",
			wantID: "CWE-284",
		},
		{
			name:   "Prototype pollution",
			input:  "prototype_pollution",
			wantID: "CWE-915",
		},
		{
			name:   "Open redirect",
			input:  "open_redirect",
			wantID: "CWE-601",
		},
		{
			name:   "Auth bypass",
			input:  "auth_bypass",
			wantID: "CWE-287",
		},
		{
			name:   "Race condition",
			input:  "race_condition",
			wantID: "CWE-362",
		},
		{
			name:   "HTTP smuggling",
			input:  "smuggling",
			wantID: "CWE-444",
		},
		{
			name:   "Business logic",
			input:  "bizlogic",
			wantID: "CWE-840",
		},
		{
			name:   "DOM XSS",
			input:  "dom_xss",
			wantID: "CWE-79",
		},
		{
			name:   "GraphQL",
			input:  "graphql",
			wantID: "CWE-939",
		},
		{
			name:   "Cloud",
			input:  "cloud",
			wantID: "CWE-284",
		},
		{
			name:   "Container escape",
			input:  "container_escape",
			wantID: "CWE-250",
		},
		{
			name:   "Second order",
			input:  "second_order",
			wantID: "CWE-94",
		},
		{
			name:   "Blind SQLi",
			input:  "blindsqli",
			wantID: "CWE-89",
		},
		{
			name:   "WebSocket",
			input:  "websocket",
			wantID: "CWE-346",
		},
		{
			name:   "Info disclosure",
			input:  "info_disclosure",
			wantID: "CWE-200",
		},
		{
			name:   "Hardcoded secret",
			input:  "hardcoded_secret",
			wantID: "CWE-798",
		},
		{
			name:   "Weak crypto",
			input:  "weak_crypto",
			wantID: "CWE-327",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := Lookup(tc.input)
			if entry.ID != tc.wantID {
				t.Errorf("Lookup(%q).ID = %q, want %q", tc.input, entry.ID, tc.wantID)
			}
		})
	}
}

func TestLookup_Unknown(t *testing.T) {
	entry := Lookup("nonexistent_vulnerability_type")
	if entry.ID != "CWE-676" {
		t.Errorf("expected CWE-676 for unknown type, got %s", entry.ID)
	}
	if entry.Description == "" {
		t.Error("expected non-empty description for default CWE")
	}
}

func TestLookup_EmptyString(t *testing.T) {
	entry := Lookup("")
	if entry.ID == "" {
		t.Error("expected a non-empty CWE ID for empty string")
	}
}

func TestLookup_CaseInsensitive(t *testing.T) {
	entry := Lookup("SQLI")
	if entry.ID != "CWE-89" {
		t.Errorf("expected CWE-89, got %s", entry.ID)
	}

	entry = Lookup("XSS")
	if entry.ID != "CWE-79" {
		t.Errorf("expected CWE-79, got %s", entry.ID)
	}
}

func TestLookup_PartialMatch(t *testing.T) {
	entry := Lookup("sqli_injection")
	if entry.ID != "CWE-89" {
		t.Errorf("expected CWE-89 for partial match 'sqli_injection', got %s", entry.ID)
	}
}

func TestLookupByID(t *testing.T) {
	tests := []struct {
		id   string
		name string
	}{
		{"CWE-89", "Improper Neutralization of Special Elements used in an SQL Command"},
		{"CWE-79", "Improper Neutralization of Input During Web Page Generation"},
		{"CWE-918", "Server-Side Request Forgery"},
		{"CWE-94", "Improper Control of Generation of Code"},
		{"CWE-502", "Deserialization of Untrusted Data"},
		{"CWE-22", "Improper Limitation of a Pathname to a Restricted Directory"},
		{"CWE-352", "Cross-Site Request Forgery"},
		{"CWE-611", "Improper Restriction of XML External Entity Reference"},
	}

	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			entry := LookupByID(tc.id)
			if entry.ID != tc.id {
				t.Errorf("LookupByID(%q).ID = %q, want %q", tc.id, entry.ID, tc.id)
			}
			if entry.Name != tc.name {
				t.Errorf("LookupByID(%q).Name = %q, want %q", tc.id, entry.Name, tc.name)
			}
		})
	}
}

func TestLookupByID_Unknown(t *testing.T) {
	entry := LookupByID("CWE-9999")
	if entry.ID != "" {
		t.Errorf("expected empty entry for unknown CWE, got %+v", entry)
	}
	if entry.Name != "" {
		t.Error("expected empty name for unknown CWE")
	}
}

func TestLookupByID_EmptyString(t *testing.T) {
	entry := LookupByID("")
	if entry.ID != "" {
		t.Error("expected empty entry for empty string")
	}
}

func TestLookupByID_SameIDMultipleEntries(t *testing.T) {
	entry := LookupByID("CWE-98")
	if entry.ID != "CWE-98" {
		t.Errorf("expected CWE-98, got %s", entry.ID)
	}
}

func TestLookupByID_SameIDMultipleItems(t *testing.T) {
	entry := LookupByID("CWE-284")
	if entry.ID != "CWE-284" {
		t.Errorf("expected CWE-284, got %s", entry.ID)
	}
}

func TestAllCWEs(t *testing.T) {
	entries := AllCWEs()
	if len(entries) == 0 {
		t.Fatal("AllCWEs() returned empty slice")
	}

	seen := make(map[string]bool)
	for _, e := range entries {
		if e.ID == "" {
			t.Error("found entry with empty ID")
		}
		if e.Name == "" {
			t.Errorf("entry %s has empty name", e.ID)
		}
		if e.Description == "" {
			t.Errorf("entry %s has empty description", e.ID)
		}
		if e.URL == "" {
			t.Errorf("entry %s has empty URL", e.ID)
		}
		key := e.ID + ":" + e.Name + ":" + e.Description
		if seen[key] {
			t.Errorf("duplicate entry: %s", key)
		}
		seen[key] = true
	}
}

func TestAllCWEs_ContainsExpected(t *testing.T) {
	entries := AllCWEs()
	found := false
	for _, e := range entries {
		if e.ID == "CWE-89" {
			found = true
			break
		}
	}
	if !found {
		t.Error("AllCWEs() should contain CWE-89")
	}
}

func TestFindingsWithCWE(t *testing.T) {
	findings := []FindingWithCWE{
		{Type: "sqli"},
		{Type: "xss"},
		{Type: "unknown_type"},
	}

	result := FindingsWithCWE(findings)

	if result[0].CWE != "CWE-89" {
		t.Errorf("expected CWE-89 for sqli, got %s", result[0].CWE)
	}
	if result[1].CWE != "CWE-79" {
		t.Errorf("expected CWE-79 for xss, got %s", result[1].CWE)
	}
	if result[2].CWE != "CWE-676" {
		t.Errorf("expected CWE-676 for unknown, got %s", result[2].CWE)
	}
}

func TestFindingsWithCWE_Empty(t *testing.T) {
	result := FindingsWithCWE(nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestFindingsWithCWE_AlreadyHasCWE(t *testing.T) {
	findings := []FindingWithCWE{
		{Type: "sqli", CWE: "CWE-999", CWEName: "Custom"},
	}
	result := FindingsWithCWE(findings)
	if result[0].CWE != "CWE-999" {
		t.Error("should not overwrite existing CWE")
	}
}

func TestCWEEntry_Fields(t *testing.T) {
	sqli := Lookup("sqli")
	if sqli.ID != "CWE-89" {
		t.Errorf("ID = %s", sqli.ID)
	}
	if sqli.Name == "" {
		t.Error("Name should not be empty")
	}
	if sqli.Description == "" {
		t.Error("Description should not be empty")
	}
	if sqli.URL == "" {
		t.Error("URL should not be empty")
	}
	if sqli.URL != "https://cwe.mitre.org/data/definitions/89.html" {
		t.Errorf("unexpected URL: %s", sqli.URL)
	}
}

func TestLookup_Consistency(t *testing.T) {
	for key, entry := range cweMap {
		byID := LookupByID(entry.ID)
		if byID.ID != entry.ID {
			t.Errorf("LookupByID(%s) returned %q, expected %q", entry.ID, byID.ID, entry.ID)
		}

		byType := Lookup(key)
		if byType.ID != entry.ID {
			t.Errorf("Lookup(%q) returned %s, expected %s", key, byType.ID, entry.ID)
		}
	}
}

func TestDomainXSSAndXSS(t *testing.T) {
	xss := Lookup("xss")
	domXSS := Lookup("dom_xss")
	if xss.ID != domXSS.ID {
		t.Error("xss and dom_xss should map to same CWE-79")
	}
}

func TestBlindSQLiAndSQLi(t *testing.T) {
	sqli := Lookup("sqli")
	blindsqli := Lookup("blindsqli")
	if sqli.ID != blindsqli.ID {
		t.Error("sqli and blindsqli should map to same CWE-89")
	}
}

func TestSecondOrderAndRCEShareID(t *testing.T) {
	rce := Lookup("rce")
	second := Lookup("second_order")
	if rce.ID != second.ID {
		t.Error("rce and second_order should map to same CWE-94")
	}
}

func TestLookup_SubstringFallback(t *testing.T) {
	entry := Lookup("xss_vulnerability_in_dom")
	if entry.ID != "CWE-79" {
		t.Errorf("expected CWE-79 via substring fallback, got %s", entry.ID)
	}
}
