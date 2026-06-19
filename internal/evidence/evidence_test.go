package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewEvidenceManager(t *testing.T) {
	m := NewEvidenceManager("./test_evidence")
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestExportEvidence(t *testing.T) {
	ev := &Evidence{
		ID:          "EVID-001",
		Type:        EvidenceTypeXSSReflection,
		Target:      "example.com",
		Technique:   "XSS",
		Payload:     "<script>alert(1)</script>",
		CollectedAt: time.Now(),
	}
	data, err := ExportEvidence(ev)
	if err != nil {
		t.Fatalf("ExportEvidence error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty export")
	}
}

func TestExportEvidenceNil(t *testing.T) {
	_, err := ExportEvidence(nil)
	if err == nil {
		t.Error("expected error for nil evidence")
	}
}

func TestImportEvidence(t *testing.T) {
	ev := &Evidence{
		ID:          "EVID-002",
		Type:        EvidenceTypeXSSReflection,
		Target:      "import-test.com",
		Technique:   "SQLi",
		CollectedAt: time.Now(),
	}
	data, _ := ExportEvidence(ev)
	imported, err := ImportEvidence(data)
	if err != nil {
		t.Fatalf("ImportEvidence error: %v", err)
	}
	if imported.ID != "EVID-002" {
		t.Errorf("expected EVID-002, got %s", imported.ID)
	}
}

func TestImportEvidenceInvalid(t *testing.T) {
	_, err := ImportEvidence([]byte("invalid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSaveEvidenceToFile(t *testing.T) {
	dir := t.TempDir()
	ev := &Evidence{
		ID:          "EVID-003",
		Type:        EvidenceTypeXSSReflection,
		Target:      "save-test.com",
		CollectedAt: time.Now(),
	}
	err := SaveEvidenceToFile(dir, ev, nil)
	if err != nil {
		t.Fatalf("SaveEvidenceToFile error: %v", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir error: %v", err)
	}
	if len(files) == 0 {
		t.Error("expected at least 1 file")
	}
}

func TestSaveEvidenceToFileNoID(t *testing.T) {
	ev := &Evidence{
		Type: EvidenceTypeXSSReflection,
	}
	err := SaveEvidenceToFile(t.TempDir(), ev, nil)
	if err == nil {
		t.Error("expected error for evidence without ID")
	}
}

func TestEvidenceTypes(t *testing.T) {
	tests := []struct {
		et   EvidenceType
		want string
	}{
		{EvidenceTypeXSSReflection, "xss_reflection"},
		{EvidenceTypeCommandOutput, "command_output"},
		{EvidenceTypeFileContent, "file_content"},
		{EvidenceTypeNetworkInfo, "network_info"},
		{EvidenceTypeCredential, "credential"},
		{EvidenceTypeWebShell, "web_shell"},
		{EvidenceTypePersistence, "persistence"},
		{EvidenceTypeDatabaseInfo, "database_info"},
	}
	for _, tt := range tests {
		got := string(tt.et)
		if got != tt.want {
			t.Errorf("EvidenceType = %s, want %s", got, tt.want)
		}
	}
}

func TestSanitizeEvidence(t *testing.T) {
	ev := &Evidence{
		ID:          "EVID-SAN",
		Type:        EvidenceTypeCredential,
		Target:      "test.com",
		Technique:   "password_capture",
		Payload:     "password=secret",
		Description: "found credentials",
		Tags:        []string{"high", "password_secret"},
		CollectedAt: time.Now(),
	}
	sanitizeEvidence(ev)
}

func TestHMACIntegrity(t *testing.T) {
	key := []byte("test-hmac-key")
	ev := &Evidence{
		ID:          "EVID-HMAC",
		Type:        EvidenceTypeCommandOutput,
		Target:      "hmac-test.com",
		CollectedAt: time.Now(),
	}
	dir := t.TempDir()
	err := SaveEvidenceToFile(dir, ev, key)
	if err != nil {
		t.Fatalf("SaveEvidenceToFile error: %v", err)
	}
	path := filepath.Join(dir, ev.ID+".json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("evidence file not found: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty file")
	}
}
