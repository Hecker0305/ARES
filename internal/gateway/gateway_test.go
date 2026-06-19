package gateway

import (
	"testing"
)

func TestNewGateway(t *testing.T) {
	gw := New(nil, nil, nil)
	if gw == nil {
		t.Fatal("expected non-nil gateway")
	}
}

func TestRegister(t *testing.T) {
	gw := New(nil, nil, nil)
	gw.Register(ToolSchema{
		Name:        "test_tool",
		Description: "A test tool",
	})
	schema := gw.SchemaFor("test_tool")
	if schema == nil {
		t.Fatal("expected schema")
	}
	if schema.Name != "test_tool" {
		t.Errorf("expected test_tool, got %s", schema.Name)
	}
}

func TestSchemaForNonexistent(t *testing.T) {
	gw := New(nil, nil, nil)
	schema := gw.SchemaFor("nonexistent")
	if schema != nil {
		t.Error("expected nil for nonexistent tool")
	}
}

func TestSchemas(t *testing.T) {
	gw := New(nil, nil, nil)
	gw.Register(ToolSchema{Name: "tool1"})
	gw.Register(ToolSchema{Name: "tool2"})
	schemas := gw.Schemas()
	if len(schemas) < 6 {
		t.Errorf("expected at least 6 schemas (5 default + 2 custom), got %d", len(schemas))
	}
}

func TestDefaultSchemas(t *testing.T) {
	gw := New(nil, nil, nil)
	schemas := gw.Schemas()
	names := make(map[string]bool)
	for _, s := range schemas {
		names[s.Name] = true
	}
	expected := []string{"terminal_execute", "web_request", "file_read", "network_scan", "vuln_scan", "exploit"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("expected default schema %s", name)
		}
	}
}

func TestAuditLog(t *testing.T) {
	gw := New(nil, nil, nil)
	log := gw.AuditLog()
	if log == nil {
		t.Error("expected non-nil audit log")
	}
}

func TestStats(t *testing.T) {
	gw := New(nil, nil, nil)
	stats := gw.Stats()
	if stats["schemas"].(int) < 5 {
		t.Errorf("expected at least 5 schemas, got %d", stats["schemas"])
	}
}

func TestToolToPolicyAction(t *testing.T) {
	gw := New(nil, nil, nil)
	tests := []struct {
		tool string
		want string
	}{
		{"nmap_scan", "network_scan"},
		{"terminal_execute", "exec_command"},
		{"file_read_tool", "file_read"},
		{"file_write_tool", "file_read"},
		{"web_request", "web_request"},
		{"exploit_tool", "network_scan"},
		{"unknown", "exec_command"},
	}
	for _, tt := range tests {
		got := gw.toolToPolicyAction(tt.tool)
		if string(got) != tt.want {
			t.Errorf("toolToPolicyAction(%q) = %s, want %s", tt.tool, got, tt.want)
		}
	}
}
