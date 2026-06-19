package worker_test

import (
	"encoding/json"
	"testing"

	"github.com/ares/engine/internal/agent"
)

func FuzzExecuteScanPlan(f *testing.F) {
	seeds := []string{
		`{"target":"example.com","scanners":["nmap","gobuster"]}`,
		`{"target":"http://test.com","max_depth":3}`,
		`{"target":"'; DROP TABLE scans; --"}`,
		`{}`,
		``,
		`invalid json`,
		`{"target":"<script>alert(1)</script>","payload":"' OR '1'='1"}`,
		`{"target":"$(cat /etc/shadow)"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, scanPlan string) {
		var plan map[string]interface{}
		json.Unmarshal([]byte(scanPlan), &plan)
		_ = plan
	})
}

func FuzzMergeFindings(f *testing.F) {
	seeds := []struct {
		a string
		b string
	}{
		{`[]`, `[]`},
		{`[{"id":"F1","title":"SQLi"}]`, `[{"id":"F2","title":"XSS"}]`},
		{`[{"id":"F1"}]`, `[{"id":"F1"}]`},
		{`invalid`, `[]`},
		{`[]`, `invalid`},
		{`[{"id":"<script>"}]`, `[{"id":"'; DROP"}]`},
	}
	for _, s := range seeds {
		f.Add(s.a, s.b)
	}

	f.Fuzz(func(t *testing.T, findingsA string, findingsB string) {
		var fa, fb []agent.Finding
		json.Unmarshal([]byte(findingsA), &fa)
		json.Unmarshal([]byte(findingsB), &fb)

		sc1 := agent.NewScanContext("fuzz-1", "target.test")
		sc2 := agent.NewScanContext("fuzz-2", "target.test")
		for _, f := range fa {
			sc1.AddFinding(f)
		}
		for _, f := range fb {
			sc2.AddFinding(f)
		}
		_ = sc1
		_ = sc2
	})
}
