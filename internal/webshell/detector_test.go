package webshell

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasDoubleExtension(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"file.php", false},
		{"image.php.jpg", true},
	}
	for _, tt := range tests {
		if got := hasDoubleExtension(tt.name); got != tt.want {
			t.Errorf("hasDoubleExtension(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsScriptExtension(t *testing.T) {
	tests := []struct {
		ext  string
		want bool
	}{
		{".php", true}, {".aspx", true}, {".jpg", false},
	}
	for _, tt := range tests {
		if got := isScriptExtension(tt.ext); got != tt.want {
			t.Errorf("isScriptExtension(%q) = %v", tt.ext, got)
		}
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		ext  string
		want Language
	}{
		{".php", LangPHP}, {".aspx", LangASPX},
	}
	for _, tt := range tests {
		if got := detectLanguage(tt.ext); got != tt.want {
			t.Errorf("detectLanguage(%q) = %s", tt.ext, got)
		}
	}
}

func TestSignatureMatching(t *testing.T) {
	d := NewDetector(DefaultConfig())
	findings, err := d.DetectFromBytes("test.php", []byte("<?php system($_GET[\"c\"]); ?>"), nil, nil)
	if err != nil {
		t.Fatalf("DetectFromBytes failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one signature finding")
	}
	hasSig := false
	for _, f := range findings {
		if f.DetectionMethod == MethodSignature {
			hasSig = true
			break
		}
	}
	if !hasSig {
		t.Fatal("expected a signature-based finding")
	}
}

func TestCleanFile(t *testing.T) {
	d := NewDetector(DefaultConfig())
	clean := "<?php echo \"hello world\"; ?>"
	findings, err := d.DetectFromBytes("index.php", []byte(clean), nil, nil)
	if err != nil {
		t.Fatalf("DetectFromBytes failed: %v", err)
	}
	if len(findings) > 0 {
		t.Fatalf("clean file produced %d findings", len(findings))
	}
}

func TestHashDBPopulated(t *testing.T) {
	d := NewDetector(DefaultConfig())
	if len(d.hashDB) == 0 {
		t.Fatal("hash DB is empty")
	}
	for _, entry := range knownWebshells {
		if _, exists := d.hashDB[entry.SHA256]; !exists {
			t.Fatalf("known webshell %s not in hash DB", entry.Name)
		}
	}
}

func TestScanUploadDir(t *testing.T) {
	d := NewDetector(DefaultConfig())
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "shell.php"), []byte("<?php system($_GET[\"c\"]); ?>"), 0644)
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("clean file"), 0644)
	result, err := d.ScanUploadDir(nil, dir, nil)
	if err != nil {
		t.Fatalf("ScanUploadDir failed: %v", err)
	}
	if result.Scanned != 1 {
		t.Errorf("expected 1 scanned, got %d", result.Scanned)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for webshell in upload dir")
	}
}

func TestScanWebRootEmpty(t *testing.T) {
	d := NewDetector(DefaultConfig())
	result, err := d.ScanWebRoot(nil, t.TempDir())
	if err != nil {
		t.Fatalf("ScanWebRoot failed: %v", err)
	}
	if result.Scanned != 0 {
		t.Errorf("expected 0 scanned, got %d", result.Scanned)
	}
}
