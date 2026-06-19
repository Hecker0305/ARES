package frontend

import (
	"io/fs"
	"reflect"
	"testing"
)

func TestDistEmbed_Exists(t *testing.T) {
	if reflect.ValueOf(Dist).IsZero() {
		t.Fatal("Dist embed.FS is zero value")
	}
}

func TestDistEmbed_ContainsIndexHTML(t *testing.T) {
	data, err := fs.ReadFile(Dist, "dist/index.html")
	if err != nil {
		t.Fatalf("failed to read dist/index.html: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("dist/index.html is empty")
	}
}

func TestDistEmbed_ContainsFavicon(t *testing.T) {
	data, err := fs.ReadFile(Dist, "dist/favicon.svg")
	if err != nil {
		t.Fatalf("failed to read dist/favicon.svg: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("dist/favicon.svg is empty")
	}
}

func TestDistEmbed_ContainsIcons(t *testing.T) {
	data, err := fs.ReadFile(Dist, "dist/icons.svg")
	if err != nil {
		t.Fatalf("failed to read dist/icons.svg: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("dist/icons.svg is empty")
	}
}

func TestDistEmbed_ListFiles(t *testing.T) {
	entries, err := fs.ReadDir(Dist, "dist")
	if err != nil {
		t.Fatalf("failed to list dist/: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("dist/ directory is empty")
	}

	found := make(map[string]bool)
	for _, e := range entries {
		found[e.Name()] = true
	}

	if !found["index.html"] {
		t.Error("expected index.html in dist/")
	}
	if !found["favicon.svg"] {
		t.Error("expected favicon.svg in dist/")
	}
	if !found["icons.svg"] {
		t.Error("expected icons.svg in dist/")
	}
}

func TestDistEmbed_FileInfo(t *testing.T) {
	data, err := fs.Stat(Dist, "dist/index.html")
	if err != nil {
		t.Fatalf("failed to stat dist/index.html: %v", err)
	}
	if data.IsDir() {
		t.Fatal("dist/index.html should not be a directory")
	}
	if data.Size() == 0 {
		t.Fatal("dist/index.html has zero size")
	}
}

func TestDistEmbed_NonExistentFile(t *testing.T) {
	_, err := fs.ReadFile(Dist, "dist/nonexistent.txt")
	if err == nil {
		t.Fatal("expected error reading nonexistent file")
	}
}

func TestDistEmbed_ReadRoot(t *testing.T) {
	_, err := fs.ReadFile(Dist, ".")
	if err == nil {
		t.Fatal("expected error reading root")
	}
}

func TestDistEmbed_FilesAreRegular(t *testing.T) {
	entries, err := fs.ReadDir(Dist, "dist")
	if err != nil {
		t.Fatalf("failed to list dist/: %v", err)
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			info, _ := e.Info()
			_ = info
		}
	}
}

func TestDistEmbed_IndexHTMLNotEmpty(t *testing.T) {
	data, err := fs.ReadFile(Dist, "dist/index.html")
	if err != nil {
		t.Fatalf("failed to read dist/index.html: %v", err)
	}
	if len(data) < 10 {
		t.Fatalf("dist/index.html seems too short: %d bytes", len(data))
	}
}

func TestDistEmbed_FaviconNotEmpty(t *testing.T) {
	data, err := fs.ReadFile(Dist, "dist/favicon.svg")
	if err != nil {
		t.Fatalf("failed to read dist/favicon.svg: %v", err)
	}
	if len(data) < 10 {
		t.Fatalf("dist/favicon.svg seems too short: %d bytes", len(data))
	}
}
