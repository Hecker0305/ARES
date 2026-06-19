package metrics

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Counter struct {
	value atomic.Int64
}

func (c *Counter) Inc()         { c.value.Add(1) }
func (c *Counter) Add(n int64)  { c.value.Add(n) }
func (c *Counter) Value() int64 { return c.value.Load() }

type Gauge struct {
	value atomic.Int64
}

func (g *Gauge) Set(v float64)  { g.value.Store(int64(v * 1000)) }
func (g *Gauge) Value() float64 { return float64(g.value.Load()) / 1000 }

type Histogram struct {
	mu      sync.Mutex
	total   int64
	sum     float64
	buckets []float64
	counts  []int64
	inf     int64
}

func NewHistogram(buckets []float64) *Histogram {
	return &Histogram{
		buckets: buckets,
		counts:  make([]int64, len(buckets)+1),
	}
}

func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.total++
	h.sum += v
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
			return
		}
	}
	h.inf++
}

func (h *Histogram) Snapshot() map[string]interface{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	buckets := make([]map[string]interface{}, 0, len(h.counts))
	for i, c := range h.counts {
		if i < len(h.buckets) {
			buckets = append(buckets, map[string]interface{}{
				"upper": h.buckets[i],
				"count": c,
			})
		} else {
			buckets = append(buckets, map[string]interface{}{
				"upper": "+Inf",
				"count": c,
			})
		}
	}
	avg := 0.0
	if h.total > 0 {
		avg = h.sum / float64(h.total)
	}
	return map[string]interface{}{
		"total":   h.total,
		"sum":     h.sum,
		"avg":     avg,
		"buckets": buckets,
	}
}

type Snapshot struct {
	Counters   map[string]int64
	Gauges     map[string]float64
	Histograms map[string]map[string]interface{}
	Uptime     string
}

type Metrics struct {
	mu        sync.RWMutex
	startTime time.Time

	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram

	RequestCount      atomic.Int64
	RequestErrors     atomic.Int64
	RequestDurationMs atomic.Int64
	ActiveRequests    atomic.Int64

	DaemonCalls       atomic.Int64
	DaemonErrors      atomic.Int64
	DaemonRestarts    atomic.Int64
	DaemonCircuitOpen atomic.Int64

	YaraScans    atomic.Int64
	DisasmCalls  atomic.Int64
	ScapySends   atomic.Int64
	CapaAnalyses atomic.Int64

	Injections  atomic.Int64
	MITMRelays  atomic.Int64
	ProxyChains atomic.Int64
	Simulations atomic.Int64

	AgentsRegistered atomic.Int64
	TasksCreated     atomic.Int64
	ImplantGenerated atomic.Int64

	timingBuckets map[string]*TimingBucket
}

type TimingBucket struct {
	mu    sync.Mutex
	count int64
	sum   float64
	min   float64
	max   float64
}

var global = &Metrics{
	startTime:     time.Now(),
	counters:      make(map[string]*Counter),
	gauges:        make(map[string]*Gauge),
	histograms:    make(map[string]*Histogram),
	timingBuckets: make(map[string]*TimingBucket),
}

func Get() *Metrics {
	return global
}

func GetRegistry() *Metrics {
	return global
}

func (m *Metrics) Counter(name string) *Counter {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.counters[name]
	if !ok {
		c = &Counter{}
		m.counters[name] = c
	}
	return c
}

func (m *Metrics) Gauge(name string) *Gauge {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.gauges[name]
	if !ok {
		g = &Gauge{}
		m.gauges[name] = g
	}
	return g
}

func (m *Metrics) Histogram(name string, buckets []float64) *Histogram {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.histograms[name]
	if !ok {
		h = NewHistogram(buckets)
		m.histograms[name] = h
	}
	return h
}

func (m *Metrics) IncDaemonCalls()       { m.DaemonCalls.Add(1) }
func (m *Metrics) IncDaemonErrors()      { m.DaemonErrors.Add(1) }
func (m *Metrics) IncDaemonRestarts()    { m.DaemonRestarts.Add(1) }
func (m *Metrics) IncDaemonCircuitOpen() { m.DaemonCircuitOpen.Add(1) }
func (m *Metrics) IncYaraScans()         { m.YaraScans.Add(1) }
func (m *Metrics) IncDisasmCalls()       { m.DisasmCalls.Add(1) }
func (m *Metrics) IncScapySends()        { m.ScapySends.Add(1) }
func (m *Metrics) IncCapaAnalyses()      { m.CapaAnalyses.Add(1) }
func (m *Metrics) IncInjections()        { m.Injections.Add(1) }
func (m *Metrics) IncMITMRelays()        { m.MITMRelays.Add(1) }
func (m *Metrics) IncProxyChains()       { m.ProxyChains.Add(1) }
func (m *Metrics) IncSimulations()       { m.Simulations.Add(1) }
func (m *Metrics) IncAgentsRegistered()  { m.AgentsRegistered.Add(1) }
func (m *Metrics) IncTasksCreated()      { m.TasksCreated.Add(1) }
func (m *Metrics) IncImplantGenerated()  { m.ImplantGenerated.Add(1) }

func (m *Metrics) AddRequest(dur time.Duration, err bool) {
	m.RequestCount.Add(1)
	m.RequestDurationMs.Add(dur.Milliseconds())
	if err {
		m.RequestErrors.Add(1)
	}
}

func (m *Metrics) ObserveTiming(bucket string, dur time.Duration) {
	m.mu.Lock()
	b, ok := m.timingBuckets[bucket]
	if !ok {
		b = &TimingBucket{}
		m.timingBuckets[bucket] = b
	}
	m.mu.Unlock()

	ms := dur.Seconds() * 1000
	b.mu.Lock()
	b.count++
	b.sum += ms
	if ms < b.min || b.count == 1 {
		b.min = ms
	}
	if ms > b.max {
		b.max = ms
	}
	b.mu.Unlock()
}

func (m *Metrics) Snapshot() *Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snap := &Snapshot{
		Counters:   make(map[string]int64),
		Gauges:     make(map[string]float64),
		Histograms: make(map[string]map[string]interface{}),
		Uptime:     time.Since(m.startTime).Round(time.Second).String(),
	}

	for name, c := range m.counters {
		snap.Counters[name] = c.Value()
	}

	for name, g := range m.gauges {
		snap.Gauges[name] = g.Value()
	}

	for name, h := range m.histograms {
		snap.Histograms[name] = h.Snapshot()
	}

	return snap
}

func CounterInc(name string) {
	global.mu.Lock()
	c, ok := global.counters[name]
	if !ok {
		c = &Counter{}
		global.counters[name] = c
	}
	global.mu.Unlock()
	c.Inc()
}

func CounterAdd(name string, n int64) {
	global.mu.Lock()
	c, ok := global.counters[name]
	if !ok {
		c = &Counter{}
		global.counters[name] = c
	}
	global.mu.Unlock()
	c.Add(n)
}

func GaugeSet(name string, v float64) {
	global.mu.Lock()
	g, ok := global.gauges[name]
	if !ok {
		g = &Gauge{}
		global.gauges[name] = g
	}
	global.mu.Unlock()
	g.Set(v)
}

func Observe(name string, value float64) {
	global.mu.Lock()
	h, ok := global.histograms[name]
	if !ok {
		h = NewHistogram(nil)
		global.histograms[name] = h
	}
	global.mu.Unlock()
	h.Observe(value)
}

func PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := global.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snap)
	}
}
