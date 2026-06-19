package diff

import "testing"

func TestCompareStrings(t *testing.T) {
	diffs := CompareStrings("hello world", "hello there")
	if len(diffs) == 0 {
		t.Error("expected diffs")
	}
}

func TestCompareStringsEqual(t *testing.T) {
	diffs := CompareStrings("same", "same")
	if len(diffs) != 1 || diffs[0].Type != DiffEqual {
		t.Errorf("expected 1 equal diff, got %d", len(diffs))
	}
}

func TestCompareStringsEmpty(t *testing.T) {
	diffs := CompareStrings("", "new")
	if len(diffs) == 0 {
		t.Error("expected diffs for new content")
	}
}

func TestCompareStringsInline(t *testing.T) {
	diffs := CompareStringsInline("hello world", "hello there")
	if len(diffs) == 0 {
		t.Error("expected inline diffs")
	}
}

func TestFormatDiffs(t *testing.T) {
	diffs := CompareStrings("old", "new")
	result := FormatDiffs(diffs, 1)
	if result == "" {
		t.Error("expected formatted output")
	}
}

func TestCountChanges(t *testing.T) {
	diffs := []Diff{
		{Type: DiffAdded},
		{Type: DiffRemoved},
		{Type: DiffModified},
	}
	a, r, m := CountChanges(diffs)
	if a != 1 || r != 1 || m != 1 {
		t.Errorf("expected 1 each, got added=%d removed=%d modified=%d", a, r, m)
	}
}

func TestDiffString(t *testing.T) {
	d := Diff{Type: DiffAdded, New: "new line"}
	s := d.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
}
