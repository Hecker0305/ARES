package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "store-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestNew(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.dataDir != dir {
		t.Errorf("expected dataDir %s, got %s", dir, s.dataDir)
	}
	s.Close()
}

func TestStore_SaveAndGetScan(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	scan := &PersistedScan{ID: "scan-1", Target: "example.com", Status: "running", StartTime: time.Now()}
	s.SaveScan(scan)
	got := s.GetScan("scan-1")
	if got == nil {
		t.Fatal("expected scan")
	}
	if got.ID != "scan-1" || got.Target != "example.com" {
		t.Errorf("unexpected scan: %+v", got)
	}
}

func TestStore_GetScanNotFound(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	got := s.GetScan("nonexistent")
	if got != nil {
		t.Fatal("expected nil for nonexistent scan")
	}
}

func TestStore_DeleteScan(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	s.SaveScan(&PersistedScan{ID: "scan-1", Target: "x"})
	s.DeleteScan("scan-1")
	if s.GetScan("scan-1") != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestStore_ListScans(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	s.SaveScan(&PersistedScan{ID: "s1", Target: "a.com", TenantID: "tenant-1"})
	s.SaveScan(&PersistedScan{ID: "s2", Target: "b.com", TenantID: "tenant-1"})
	s.SaveScan(&PersistedScan{ID: "s3", Target: "c.com", TenantID: "tenant-2"})

	all := s.ListScans("")
	if len(all) != 3 {
		t.Errorf("expected 3 scans, got %d", len(all))
	}

	tenant1 := s.ListScans("tenant-1")
	if len(tenant1) != 2 {
		t.Errorf("expected 2 scans for tenant-1, got %d", len(tenant1))
	}

	tenant2 := s.ListScans("tenant-2")
	if len(tenant2) != 1 {
		t.Errorf("expected 1 scan for tenant-2, got %d", len(tenant2))
	}

	none := s.ListScans("nonexistent")
	if len(none) != 0 {
		t.Errorf("expected 0 scans for nonexistent tenant, got %d", len(none))
	}
}

func TestStore_SaveAndGetFinding(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	f := &PersistedFinding{ID: "f-1", ScanID: "s-1", Type: "xss", Severity: "high", Target: "x.com", Title: "XSS Found"}
	s.SaveFinding(f)
	got := s.GetFinding("f-1")
	if got == nil {
		t.Fatal("expected finding")
	}
	if got.ID != "f-1" || got.Title != "XSS Found" {
		t.Errorf("unexpected finding: %+v", got)
	}
}

func TestStore_GetFindingNotFound(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	got := s.GetFinding("nonexistent")
	if got != nil {
		t.Fatal("expected nil for nonexistent finding")
	}
}

func TestStore_ListFindings(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	s.SaveFinding(&PersistedFinding{ID: "f1", ScanID: "s-1"})
	s.SaveFinding(&PersistedFinding{ID: "f2", ScanID: "s-1"})
	s.SaveFinding(&PersistedFinding{ID: "f3", ScanID: "s-2"})

	all := s.ListFindings("")
	if len(all) != 3 {
		t.Errorf("expected 3 findings, got %d", len(all))
	}

	scan1 := s.ListFindings("s-1")
	if len(scan1) != 2 {
		t.Errorf("expected 2 findings for s-1, got %d", len(scan1))
	}

	scan2 := s.ListFindings("s-2")
	if len(scan2) != 1 {
		t.Errorf("expected 1 finding for s-2, got %d", len(scan2))
	}

	empty := s.ListFindings("nonexistent")
	if len(empty) != 0 {
		t.Errorf("expected 0 findings, got %d", len(empty))
	}
}

func TestStore_SaveAndGetSession(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	session := &PersistedSession{Token: "tok-1", Username: "alice", Role: "admin", ExpiresAt: time.Now().Add(time.Hour)}
	s.SaveSession(session)
	got := s.GetSession("tok-1")
	if got == nil {
		t.Fatal("expected session")
	}
	if got.Username != "alice" || got.Role != "admin" {
		t.Errorf("unexpected session: %+v", got)
	}
}

func TestStore_GetSessionNotFound(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	got := s.GetSession("nonexistent")
	if got != nil {
		t.Fatal("expected nil")
	}
}

func TestStore_DeleteSession(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	s.SaveSession(&PersistedSession{Token: "tok-1", Username: "u", Role: "r"})
	s.DeleteSession("tok-1")
	if s.GetSession("tok-1") != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestStore_SaveAndListWebhooks(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	s.SaveWebhook(&WebhookEntry{ID: "w-1", URL: "https://hook.example.com", Type: "slack", Events: "scan.complete", Enabled: true})
	s.SaveWebhook(&WebhookEntry{ID: "w-2", URL: "https://hook2.example.com", Type: "web", Events: "finding.critical", Enabled: false})

	list := s.ListWebhooks()
	if len(list) != 2 {
		t.Errorf("expected 2 webhooks, got %d", len(list))
	}
}

func TestStore_DeleteWebhook(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	s.SaveWebhook(&WebhookEntry{ID: "w-1", URL: "https://hook.example.com", Type: "slack", Events: "scan.complete", Enabled: true})
	s.DeleteWebhook("w-1")
	if len(s.ListWebhooks()) != 0 {
		t.Fatal("expected 0 webhooks after delete")
	}
}

func TestStore_Persistence(t *testing.T) {
	dir := tempDir(t)
	func() {
		s := New(dir)
		s.SaveScan(&PersistedScan{ID: "s1", Target: "example.com", Status: "done"})
		s.SaveFinding(&PersistedFinding{ID: "f1", ScanID: "s1", Type: "sqli", Severity: "critical"})
		s.SaveSession(&PersistedSession{Token: "t1", Username: "u", Role: "r"})
		s.SaveWebhook(&WebhookEntry{ID: "w1", URL: "https://hook.com", Type: "slack", Enabled: true})
		s.flush()
		s.Close()
	}()

	s2 := New(dir)
	defer s2.Close()

	if got := s2.GetScan("s1"); got == nil || got.ID != "s1" {
		t.Fatal("expected persisted scan")
	}
	if got := s2.GetFinding("f1"); got == nil || got.ID != "f1" {
		t.Fatal("expected persisted finding")
	}
	if got := s2.GetSession("t1"); got == nil || got.Username != "u" {
		t.Fatal("expected persisted session")
	}
	if hooks := s2.ListWebhooks(); len(hooks) != 1 {
		t.Fatal("expected persisted webhook")
	}
}

func TestStore_Flush_NoDirty(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	s.flush()
	s.Close()
}

func TestStore_WriteFile_Error(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	s.writeFile("", "data")
}

func TestStore_LoadFile_NonExistent(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	var m map[string]string
	s.loadFile("nonexistent.json", &m)
	if m != nil {
		t.Fatal("expected nil map for nonexistent file")
	}
}

func TestStore_LoadFile_InvalidJSON(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid}"), 0600)

	s := New(dir)
	defer s.Close()

	var m map[string]string
	s.loadFile("bad.json", &m)
}

func TestStore_NewWithTicker(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	_ = s.saveTicker
	s.Close()
}

func TestPersistedScan_ZeroValues(t *testing.T) {
	var s PersistedScan
	if s.ID != "" {
		t.Error("expected empty ID")
	}
	if s.Findings != nil {
		t.Error("expected nil findings")
	}
}

func TestPersistedFinding_ZeroValues(t *testing.T) {
	var f PersistedFinding
	if f.Evidence != nil {
		t.Error("expected nil evidence")
	}
	if f.MitreTags != nil {
		t.Error("expected nil mitre tags")
	}
}

func TestStore_ConcurrentAccess(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	done := make(chan bool)
	go func() {
		for i := 0; i < 50; i++ {
			s.SaveScan(&PersistedScan{ID: "s1", Target: "x"})
			s.GetScan("s1")
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 50; i++ {
			s.SaveFinding(&PersistedFinding{ID: "f1", ScanID: "x"})
			s.GetFinding("f1")
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 50; i++ {
			s.ListScans("")
			s.ListFindings("")
		}
		done <- true
	}()
	<-done
	<-done
	<-done
}

func TestStore_SaveScan_Overwrite(t *testing.T) {
	dir := tempDir(t)
	s := New(dir)
	defer s.Close()

	s.SaveScan(&PersistedScan{ID: "s1", Target: "old", Status: "running"})
	s.SaveScan(&PersistedScan{ID: "s1", Target: "new", Status: "done"})
	got := s.GetScan("s1")
	if got.Target != "new" || got.Status != "done" {
		t.Errorf("expected overwritten values, got %+v", got)
	}
}
