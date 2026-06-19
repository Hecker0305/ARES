package agent

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/sandbox"
	"github.com/ares/engine/internal/security"
)

var validTargetRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

type CoordinatorConfig struct {
	NumWorkers   int
	RateLimit    time.Duration
	Timeout      time.Duration
	PauseOnPanic bool
	MaxRetries   int
	RetryDelay   time.Duration
}

type ScanTask struct {
	ID         string
	Target     string
	Targets    []string
	Prompt     string
	Phase      Phase
	Priority   int
	MaxIter    int
	OnProgress func(ScanEvent)
	OnComplete func(ScanResult)
	OnError    func(error)
}

type ScanEvent struct {
	TaskID    string    `json:"task_id"`
	Type      string    `json:"type"`
	Phase     Phase     `json:"phase"`
	Iteration int       `json:"iteration"`
	Finding   *Finding  `json:"finding,omitempty"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type ScanResult struct {
	TaskID   string        `json:"task_id"`
	State    *ScanState    `json:"state"`
	Findings []FindingData `json:"findings"`
	Duration time.Duration `json:"duration"`
	Error    error         `json:"error,omitempty"`
	Success  bool          `json:"success"`
}

type Worker struct {
	ID          int
	tasks       chan *ScanTask
	results     chan *ScanResult
	wg          sync.WaitGroup
	rateLimiter <-chan time.Time
	panicked    bool
}

type Coordinator struct {
	config  CoordinatorConfig
	workers []*Worker
	tasks   chan *ScanTask
	results chan *ScanResult
	mu      sync.RWMutex
	active  map[string]*ScanTask
	paused  map[string]bool
	events  chan ScanEvent
	tickers []*time.Ticker
}

func NewCoordinator(cfg CoordinatorConfig) *Coordinator {
	if cfg.NumWorkers == 0 {
		cfg.NumWorkers = 4
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 500 * time.Millisecond
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Minute
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = 5 * time.Second
	}

	coord := &Coordinator{
		config:  cfg,
		workers: make([]*Worker, cfg.NumWorkers),
		tasks:   make(chan *ScanTask, cfg.NumWorkers*10),
		results: make(chan *ScanResult, cfg.NumWorkers*10),
		active:  make(map[string]*ScanTask),
		paused:  make(map[string]bool),
		events:  make(chan ScanEvent, 1000),
	}

	if cfg.RateLimit > 0 {
		coord.tickers = make([]*time.Ticker, cfg.NumWorkers)
		for i := 0; i < cfg.NumWorkers; i++ {
			ticker := time.NewTicker(cfg.RateLimit)
			coord.tickers[i] = ticker
			coord.workers[i] = &Worker{
				ID:          i,
				tasks:       coord.tasks,
				results:     coord.results,
				rateLimiter: ticker.C,
			}
		}
	} else {
		for i := 0; i < cfg.NumWorkers; i++ {
			coord.workers[i] = &Worker{
				ID:      i,
				tasks:   coord.tasks,
				results: coord.results,
			}
		}
	}

	return coord
}

func (c *Coordinator) Start(ctx context.Context) {
	for i := range c.workers {
		c.workers[i].wg.Add(1)
		go c.workerLoop(ctx, c.workers[i])
	}
}

func (c *Coordinator) workerLoop(ctx context.Context, w *Worker) {
	defer w.wg.Done()

loop:
	for {
		select {
		case <-ctx.Done():
			// Drain remaining tasks on cancellation
			for {
				select {
				case task := <-c.tasks:
					if task == nil {
						break loop
					}
					result := &ScanResult{
						TaskID:  task.ID,
						Success: false,
						Error:   fmt.Errorf("scan cancelled"),
					}
					select {
					case c.results <- result:
					default:
					}
				default:
					return
				}
			}
		default:
		}

		if w.rateLimiter != nil {
			select {
			case <-ctx.Done():
				return
			case <-w.rateLimiter:
				select {
				case task := <-c.tasks:
					if task == nil {
						return
					}
					c.runTask(ctx, w, task)
				default:
				}
			}
		} else {
			select {
			case <-ctx.Done():
				return
			case task := <-c.tasks:
				if task == nil {
					return
				}
				c.runTask(ctx, w, task)
			}
		}
	}
}

func (c *Coordinator) runTask(ctx context.Context, w *Worker, task *ScanTask) {
	defer func() {
		if r := recover(); r != nil {
			w.panicked = true
			if c.config.PauseOnPanic {
				c.mu.Lock()
				c.paused[task.ID] = true
				c.mu.Unlock()
			}
			result := &ScanResult{
				TaskID:  task.ID,
				Success: false,
				Error:   fmt.Errorf("worker panic: %v", r),
			}
			select {
			case c.results <- result:
			default:
			}
			if task.OnError != nil {
				task.OnError(fmt.Errorf("worker panic: %v", r))
			}
		}
	}()

	c.mu.Lock()
	c.active[task.ID] = task
	c.mu.Unlock()

	start := time.Now()
	state := NewScanState(task.Targets)
	if task.Phase != "" {
		state.Phase = task.Phase
	}

	for iter := 0; iter < task.MaxIter; iter++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		iterEvent := ScanEvent{
			TaskID:    task.ID,
			Type:      "iteration",
			Phase:     state.Phase,
			Iteration: iter + 1,
			Timestamp: time.Now(),
		}
		if task.OnProgress != nil {
			task.OnProgress(iterEvent)
		}
		c.emitEvent(iterEvent)
		state.Iteration = iter + 1

		if task.Prompt != "" && task.Prompt != "scan" {
			spec := phaseCommandSpecFor(task, iter)
			if spec.Binary != "" {
				validated := security.ValidateCommand(spec)
				if validated.Err == nil {
					sb := sandbox.NewManager(sandbox.Config{
						Level:      sandbox.SandboxRestricted,
						Timeouts:   60 * time.Second,
						MaxOutput:  1 << 20,
						ReadOnly:   true,
						NetworkOff: false,
					})
					result := sb.Execute(ctx, validated.Binary, validated.Args, nil)
					out := result.Stdout
					violation := result.Violation
					if violation == "" && result.ExitCode != 0 {
						violation = result.Stderr
					}
					if violation == "" && out != "" {
						// Record tool output as raw data — do NOT generate synthetic findings from keyword matching
						fd := FindingData{
							Type:        "tool_output",
							Target:      task.Target,
							Payload:     spec.Binary,
							VulnType:    "raw_scan_data",
							Severity:    "info",
							Confidence:  0.0,
							RawResponse: out,
							Timestamp:   time.Now().Format(time.RFC3339),
						}
						state.RecordFinding(fd)
					}
				}
			}
		}

		if state.Iteration >= task.MaxIter {
			break
		}
	}

	result := &ScanResult{
		TaskID:   task.ID,
		State:    state,
		Findings: state.Findings,
		Duration: time.Since(start),
		Success:  true,
	}

	c.mu.Lock()
	delete(c.active, task.ID)
	delete(c.paused, task.ID)
	c.mu.Unlock()

	select {
	case c.results <- result:
	default:
	}
	if task.OnComplete != nil {
		func() {
			defer func() { recover() }()
			task.OnComplete(*result)
		}()
	}
}

func (c *Coordinator) Submit(task *ScanTask) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tasks == nil {
		return fmt.Errorf("coordinator is stopped")
	}
	if c.paused[task.ID] {
		return fmt.Errorf("task %s is paused", task.ID)
	}
	// C-02 Fix: Ensure task ID is unique and not already active to prevent race conditions on state
	if _, active := c.active[task.ID]; active {
		return fmt.Errorf("task %s is already active", task.ID)
	}
	select {
	case c.tasks <- task:
		return nil
	default:
		return fmt.Errorf("task queue full")
	}
}

func (c *Coordinator) SubmitBatch(tasks []*ScanTask) []error {
	var errs []error
	for _, task := range tasks {
		if err := c.Submit(task); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (c *Coordinator) Results() <-chan *ScanResult {
	return c.results
}

func (c *Coordinator) Events() <-chan ScanEvent {
	return c.events
}

func (c *Coordinator) emitEvent(evt ScanEvent) {
	select {
	case c.events <- evt:
	default:
	}
}

func (c *Coordinator) Pause(taskID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paused[taskID] = true
}

func (c *Coordinator) Resume(taskID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.paused, taskID)
}

func (c *Coordinator) Stop() {
	c.mu.Lock()
	for _, t := range c.tickers {
		t.Stop()
	}
	c.tickers = nil
	if c.tasks != nil {
		close(c.tasks)
		c.tasks = nil
	}
	if c.results != nil {
		close(c.results)
		c.results = nil
	}
	c.mu.Unlock()

	// Wait for all workers to finish
	for _, w := range c.workers {
		w.wg.Wait()
	}
}

func (c *Coordinator) Status() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return map[string]interface{}{
		"active_tasks": len(c.active),
		"paused_tasks": len(c.paused),
		"workers":      len(c.workers),
		"queue_size":   len(c.tasks),
		"results_size": len(c.results),
	}
}

func sanitizeTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")
	if target == "" {
		return "", fmt.Errorf("empty target")
	}
	if strings.HasPrefix(target, "-") {
		return "", fmt.Errorf("target cannot start with '-' (potential flag injection)")
	}
	if strings.ContainsAny(target, " \t\n\r") {
		return "", fmt.Errorf("target contains whitespace: %s", target)
	}
	if !validTargetRegex.MatchString(target) {
		return "", fmt.Errorf("invalid target format: %s", target)
	}
	return target, nil
}

func phaseCommandSpecFor(task *ScanTask, iter int) security.CommandSpec {
	scheme := "https"
	if strings.HasPrefix(task.Target, "http://") {
		scheme = "http"
	}

	sanitized, err := sanitizeTarget(task.Target)
	if err != nil {
		return security.CommandSpec{}
	}

	if strings.ContainsAny(sanitized, "|;&$`'\"(){}[]<>!\\\n\r") {
		return security.CommandSpec{}
	}

	switch task.Phase {
	case PhaseRecon:
		cmds := []security.CommandSpec{
			{Binary: "subfinder", Args: []string{"-d", sanitized, "-silent"}},
			{Binary: "nmap", Args: []string{"-sV", "-sC", "--open", "-T4", sanitized}},
			{Binary: "curl", Args: []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", fmt.Sprintf("%s://%s", scheme, sanitized)}},
		}
		idx := iter % len(cmds)
		return cmds[idx]
	case PhaseDiscovery:
		cmds := []security.CommandSpec{
			{Binary: "nuclei", Args: []string{"-u", fmt.Sprintf("%s://%s", scheme, sanitized), "-severity", "critical,high", "-silent"}},
		}
		idx := iter % len(cmds)
		return cmds[idx]
	case PhaseVulnScan:
		cmds := []security.CommandSpec{
			{Binary: "dalfox", Args: []string{"url", fmt.Sprintf("%s://%s", scheme, sanitized), "--silence"}},
			{Binary: "nuclei", Args: []string{"-u", fmt.Sprintf("%s://%s", scheme, sanitized), "-severity", "critical,high,medium", "-silent"}},
		}
		idx := iter % len(cmds)
		return cmds[idx]
	default:
		return security.CommandSpec{}
	}
}

type AgentsGraph struct {
	mu    sync.RWMutex
	nodes map[string]*AgentNode
	edges map[string][]string
}

type AgentNode struct {
	ID       string
	Name     string
	Type     string
	Role     string
	Parent   string
	Children []string
	State    map[string]interface{}
	Metadata map[string]string
}

func NewAgentsGraph() *AgentsGraph {
	return &AgentsGraph{
		nodes: make(map[string]*AgentNode),
		edges: make(map[string][]string),
	}
}

func (g *AgentsGraph) AddNode(node *AgentNode) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[node.ID] = node
	if node.Parent != "" {
		g.edges[node.Parent] = append(g.edges[node.Parent], node.ID)
	}
}

func (g *AgentsGraph) RemoveNode(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.nodes, id)
	delete(g.edges, id)
	for parent, children := range g.edges {
		for i, child := range children {
			if child == id {
				g.edges[parent] = append(children[:i], children[i+1:]...)
				break
			}
		}
	}
}

func (g *AgentsGraph) GetNode(id string) *AgentNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[id]
}

func (g *AgentsGraph) GetChildren(id string) []*AgentNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var children []*AgentNode
	for _, childID := range g.edges[id] {
		if node, ok := g.nodes[childID]; ok {
			children = append(children, node)
		}
	}
	return children
}

func (g *AgentsGraph) GetRoot() *AgentNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, node := range g.nodes {
		if node.Parent == "" {
			return node
		}
	}
	return nil
}
