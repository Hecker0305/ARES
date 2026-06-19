package metrics

import (
	"sync"
	"testing"
)

func TestGetRegistry(t *testing.T) {
	r := GetRegistry()
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
}

func TestCounter(t *testing.T) {
	r := GetRegistry()
	c := r.Counter("test_counter")
	if c == nil {
		t.Fatal("expected non-nil counter")
	}
	if c.Value() != 0 {
		t.Errorf("expected 0, got %d", c.Value())
	}
	c.Inc()
	if c.Value() != 1 {
		t.Errorf("expected 1, got %d", c.Value())
	}
	c.Add(5)
	if c.Value() != 6 {
		t.Errorf("expected 6, got %d", c.Value())
	}
}

func TestCounterReuse(t *testing.T) {
	r := GetRegistry()
	c1 := r.Counter("reuse")
	c2 := r.Counter("reuse")
	if c1 != c2 {
		t.Error("expected same counter instance")
	}
}

func TestGauge(t *testing.T) {
	r := GetRegistry()
	g := r.Gauge("test_gauge")
	if g == nil {
		t.Fatal("expected non-nil gauge")
	}
	g.Set(42.5)
	if g.Value() != 42.5 {
		t.Errorf("expected 42.5, got %f", g.Value())
	}
}

func TestHistogram(t *testing.T) {
	r := GetRegistry()
	h := r.Histogram("test_histogram", nil)
	if h == nil {
		t.Fatal("expected non-nil histogram")
	}
	h.Observe(0.5)
	h.Observe(1.5)
	h.Observe(3.0)

	snap := r.Snapshot()
	histData := snap.Histograms["test_histogram"]
	if histData == nil {
		t.Fatal("expected histogram data in snapshot")
	}
	total := histData["total"].(int64)
	if total != 3 {
		t.Errorf("expected 3 observations, got %d", total)
	}
}

func TestSnapshot(t *testing.T) {
	r := GetRegistry()
	r.Counter("snap_test").Add(10)
	r.Gauge("snap_gauge").Set(3.14)

	snap := r.Snapshot()
	if snap.Counters["snap_test"] != 10 {
		t.Errorf("expected 10, got %d", snap.Counters["snap_test"])
	}
	if snap.Gauges["snap_gauge"] != 3.14 {
		t.Errorf("expected 3.14, got %f", snap.Gauges["snap_gauge"])
	}
	if snap.Uptime == "" {
		t.Error("expected non-empty uptime")
	}
}

func TestCounterInc(t *testing.T) {
	CounterInc("global_counter")
	c := GetRegistry().Counter("global_counter")
	if c.Value() != 1 {
		t.Errorf("expected 1, got %d", c.Value())
	}
}

func TestCounterAdd(t *testing.T) {
	CounterAdd("global_add", 5)
	c := GetRegistry().Counter("global_add")
	if c.Value() != 5 {
		t.Errorf("expected 5, got %d", c.Value())
	}
}

func TestGaugeSet(t *testing.T) {
	GaugeSet("global_gauge", 99.9)
	g := GetRegistry().Gauge("global_gauge")
	if g.Value() != 99.9 {
		t.Errorf("expected 99.9, got %f", g.Value())
	}
}

func TestObserve(t *testing.T) {
	Observe("global_histogram", 1.0)
	Observe("global_histogram", 2.0)
	snap := GetRegistry().Snapshot()
	hist := snap.Histograms["global_histogram"]
	if hist == nil {
		t.Fatal("expected histogram data")
	}
	if hist["total"].(int64) != 2 {
		t.Errorf("expected 2, got %d", hist["total"].(int64))
	}
}

func TestCounterConcurrency(t *testing.T) {
	r := GetRegistry()
	c := r.Counter("concurrent_counter")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Inc()
		}()
	}
	wg.Wait()
	if c.Value() != 100 {
		t.Errorf("expected 100, got %d", c.Value())
	}
}

func TestGaugeConcurrency(t *testing.T) {
	r := GetRegistry()
	g := r.Gauge("concurrent_gauge")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Set(1.0)
			g.Value()
		}()
	}
	wg.Wait()
}

func TestHistogramConcurrency(t *testing.T) {
	r := GetRegistry()
	h := r.Histogram("concurrent_hist", []float64{1, 5, 10})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Observe(3.0)
		}()
	}
	wg.Wait()
	if h.total != 50 {
		t.Errorf("expected 50, got %d", h.total)
	}
}

func TestPrometheusHandler(t *testing.T) {
	r := GetRegistry()
	r.Counter("prom_test").Add(5)
	handler := PrometheusHandler()
	if handler == nil {
		t.Error("expected non-nil handler")
	}
}

func TestRegistrySnapshotConcurrency(t *testing.T) {
	r := GetRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Snapshot()
		}()
	}
	wg.Wait()
}
