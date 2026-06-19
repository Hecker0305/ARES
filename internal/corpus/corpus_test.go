package corpus

import "testing"

func testRanker(t *testing.T) *CorpusRanker {
	t.Helper()
	r, err := NewRanker()
	if err != nil {
		t.Fatalf("NewRanker: %v", err)
	}
	return r
}

func TestNewRanker(t *testing.T) {
	r := testRanker(t)
	if r == nil {
		t.Fatal("expected non-nil ranker")
	}
}

func TestPayloadCount(t *testing.T) {
	r := testRanker(t)
	count := r.PayloadCount()
	if count == 0 {
		t.Error("expected >0 default payloads")
	}
}

func TestRankedPayloads(t *testing.T) {
	r := testRanker(t)
	payloads := r.RankedPayloads("sqli", []string{"mysql"}, false)
	if len(payloads) == 0 {
		t.Log("no payloads for sqli/mysql (may need matching)")
	}
}

func TestTopN(t *testing.T) {
	r := testRanker(t)
	payloads := r.TopN(3, "xss", nil, false)
	if len(payloads) > 3 {
		t.Errorf("expected at most 3, got %d", len(payloads))
	}
}

func TestAddPayload(t *testing.T) {
	r := testRanker(t)
	r.AddPayload(Payload{Value: "test-payload", VulnClass: "test", CVSS: 5.0})
	count := r.PayloadCount()
	if count == 0 {
		t.Error("expected >0 after add")
	}
}

func TestStats(t *testing.T) {
	r := testRanker(t)
	stats := r.Stats()
	if len(stats) == 0 {
		t.Error("expected non-empty stats")
	}
}

func TestUpdateStrategicMemory(t *testing.T) {
	r := testRanker(t)
	r.UpdateStrategicMemory("' OR 1=1--", "mysql", "sqli", true)
}

func TestRankedPayloadsFilter(t *testing.T) {
	r := testRanker(t)
	payloads := r.RankedPayloads("nonexistent_vuln", nil, false)
	if len(payloads) != 0 {
		t.Errorf("expected 0 for nonexistent class, got %d", len(payloads))
	}
}
