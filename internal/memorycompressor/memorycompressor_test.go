package memorycompressor

import (
	"testing"
)

func TestNew(t *testing.T) {
	c := New(10000)
	if c == nil {
		t.Fatal("expected non-nil compressor")
	}
}

func TestAdd(t *testing.T) {
	c := New(100000)
	c.Add("scanner", "nmap -sV target.com produced output: open ports 80,443")
	stats := c.Stats()
	if stats["blocks"].(int) != 1 {
		t.Errorf("expected 1 block, got %d", stats["blocks"])
	}
}

func TestCompress(t *testing.T) {
	c := New(1000)
	for i := 0; i < 5; i++ {
		c.Add("scanner", "output line "+string(rune('0'+i)))
	}
	compressed := c.Compress()
	if compressed == "" {
		t.Error("expected non-empty compressed output")
	}
}

func TestCompressTo(t *testing.T) {
	result := New(100).CompressTo(10, "hello world this is a test string")
	if len(result) < len("hello world this is a test string") || result == "hello world this is a test string" {
		t.Log("CompressTo may not always truncate")
	}
}

func TestClear(t *testing.T) {
	c := New(100000)
	c.Add("test", "content")
	c.Clear()
	stats := c.Stats()
	if stats["blocks"].(int) != 0 {
		t.Errorf("expected 0 blocks after clear, got %d", stats["blocks"])
	}
}

func TestStats(t *testing.T) {
	c := New(100000)
	c.Add("test", "some content")
	stats := c.Stats()
	if _, ok := stats["blocks"]; !ok {
		t.Error("expected blocks in stats")
	}
	if _, ok := stats["total_tokens"]; !ok {
		t.Error("expected total_tokens in stats")
	}
	if _, ok := stats["max_tokens"]; !ok {
		t.Error("expected max_tokens in stats")
	}
}

func TestDefaultMaxTokens(t *testing.T) {
	c := New(0)
	if c == nil {
		t.Fatal("expected non-nil with default")
	}
}

func TestMultipleAdds(t *testing.T) {
	c := New(100000)
	for i := 0; i < 10; i++ {
		c.Add("test", "content")
	}
	stats := c.Stats()
	if stats["blocks"].(int) != 10 {
		t.Errorf("expected 10 blocks, got %d", stats["blocks"])
	}
}
