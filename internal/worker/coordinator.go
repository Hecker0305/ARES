package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ares/engine/internal/agent"
	"github.com/ares/engine/internal/apidiscovery"
	"github.com/ares/engine/internal/audit"
	"github.com/ares/engine/internal/authflow"
	"github.com/ares/engine/internal/bizlogic"
	"github.com/ares/engine/internal/bounty"
	"github.com/ares/engine/internal/c2"
	"github.com/ares/engine/internal/compliance"
	aresconfig "github.com/ares/engine/internal/config"
	"github.com/ares/engine/internal/control"
	"github.com/ares/engine/internal/cve"
	"github.com/ares/engine/internal/distexec"
	"github.com/ares/engine/internal/engine"
	"github.com/ares/engine/internal/escalation"
	"github.com/ares/engine/internal/evidence"
	"github.com/ares/engine/internal/federated"
	"github.com/ares/engine/internal/graph"
	"github.com/ares/engine/internal/huntmemory"
	"github.com/ares/engine/internal/integration"
	"github.com/ares/engine/internal/llm"
	"github.com/ares/engine/internal/llmrouting"
	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/multitenant"
	"github.com/ares/engine/internal/oob"
	"github.com/ares/engine/internal/otel"
	"github.com/ares/engine/internal/persistence"
	"github.com/ares/engine/internal/postexploit"
	"github.com/ares/engine/internal/report"
	resruntime "github.com/ares/engine/internal/resource"
	"github.com/ares/engine/internal/safety"
	"github.com/ares/engine/internal/sarif"
	"github.com/ares/engine/internal/scanctx"
	"github.com/ares/engine/internal/scanner"
	"github.com/ares/engine/internal/scope"
	"github.com/ares/engine/internal/secondorder"
	"github.com/ares/engine/internal/telemetry"
	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/siem"
	"github.com/ares/engine/internal/simulate"
	"github.com/ares/engine/internal/ticketing"
	"github.com/ares/engine/internal/ttp"
	"github.com/ares/engine/internal/validator"
	"github.com/ares/engine/internal/verifier"
	"github.com/ares/engine/internal/webhook"
	"github.com/ares/engine/internal/webserver"
)

// ScanProgressFn is called by the Coordinator to report scan progress.
// Callers (e.g., the web server) use this to update the in-memory scan store.
type ScanProgressFn func(scanID string, status string, phase string, progress float64, target string)

// FindingCallbackFn is called when a finding is processed during a scan.
// Callers (e.g., the web server) use this to add findings to the in-memory scan store.
type FindingCallbackFn func(scanID string, finding agent.Finding)

// EventCallbackFn is called when a lifecycle event occurs during a scan.
// Callers use this to forward events to the scan session for real-time UI updates.
type EventCallbackFn func(scanID string, evType string, message string)

type Coordinator struct {
	mu                      sync.RWMutex
	maxWorkers              int
	llm                *llm.Client
	llmRouter          *llmrouting.Router
	llmPrimary         llm.LLMClient
	llmFallback        llm.LLMClient
	llmLocal           llm.LLMClient
	outputPath              string
	outputFmt               string
	oob                     *oob.OOBServer
	dash                    *webserver.Server
	firmName                string
	evidenceManager         *evidence.EvidenceManager
	complianceReporter      *compliance.ComplianceReporter
	c2Manager               *c2.Manager
	maxIterations           int
	scanTimeout             time.Duration
	policyEngine            *control.PolicyEngine
	resourceGovernor        *resruntime.Governor
	safetyMode              *safety.SafetyModeManager
	controlEngine           *control.PolicyEngine
	webhookManager          *webhook.WebhookManager
	ticketManager           *ticketing.TicketManager
	bountyManager           *bounty.Manager
	siemClient              *siem.SIEMClient
	distOrch                *distexec.Orchestrator
	simEng                  *simulate.SimulationEngine
	graph                   *graph.AttackGraph
	escalationQueue         *escalation.Queue
	secondOrderEng          *secondorder.CorrelationEngine
	discordWebhook          *integration.DiscordWebhook
	scanControls            *ScanControls
	selectedPhases          []string
	sqliteMem               *huntmemory.SQLiteMemory
	rateLimit               float64
	rateBurst               int
	progressFn              ScanProgressFn
	findingCallback         FindingCallbackFn
	eventCallback           EventCallbackFn
	externalScanID          atomic.Value // stores string
	externalScanCredentials sync.Map    // map[string]*scanctx.CredentialSet
	bizlogicEngine          *bizlogic.Engine
	authflowEngine          *authflow.Engine
	resumeCheckpoint   *persistence.Checkpoint
	checkpointStore    *persistence.DiskStore
	checkpointDir      string
	tenantManager      *multitenant.TenantManager
	scanCounter             *multitenant.ScanCounter
	ttpRegistry             *ttp.Registry
	verifierEngine          *verifier.Engine
	scoringEngine           *engine.ScoringEngine
	confidenceGate          float64
	fpFilter                *validator.FPFilter
	apiMap                  *apidiscovery.APIMap
	attackGraph             *graph.AttackGraph
	graphPersist            *graph.PersistBackend
	cancelFuncsMu           sync.Mutex
	cancelFuncs             map[string][]context.CancelFunc
}

func NewCoordinator(maxWorkers int, client *llm.Client, outputPath, outputFmt string, oobSrv *oob.OOBServer, dash *webserver.Server, cfg *aresconfig.Config, whManager *webhook.WebhookManager) *Coordinator {
	if outputFmt == "" {
		outputFmt = "text"
	}

	evidenceManager := evidence.NewEvidenceManager("./evidence")
	complianceReporter := compliance.NewComplianceReporter(evidenceManager)

	// Enable credential dumping if env var is set (off by default for safety)
	if os.Getenv("ARES_CRED_DUMP_ENABLED") == "true" || os.Getenv("ARES_CRED_DUMP_ENABLED") == "1" {
		postexploit.SetCredDumpEnabled(true)
		authToken := os.Getenv("ARES_CRED_DUMP_AUTHZ_TOKEN")
		if authToken != "" {
			postexploit.SetCredDumpAuthz(authToken)
		}
		logger.Info("Credential dumping enabled via ARES_CRED_DUMP_ENABLED", logger.Fields{"component": "Coordinator"})
	} else {
		postexploit.SetCredDumpEnabled(false)
	}

	var c2Manager *c2.Manager
	if cfg.Sliver.Enabled {
		var err error
		c2Manager, err = c2.InitC2FromConfig(cfg)
		if err != nil {
			logger.Error("C2 init failed (Sliver disabled)", logger.Fields{"component": "Coordinator", "error": err})
			c2Manager = nil
		}
	}

	scanTimeout := time.Duration(cfg.Scan.ScanTimeoutSec) * time.Second
	if scanTimeout <= 0 {
		scanTimeout = 30 * time.Minute
	}

	// Create shared resource governor
	govCfg := resruntime.Budget{
		MaxTokens:     int64(cfg.LLM.MaxTokens * cfg.Scan.MaxIterations),
		MaxMemoryMB:   4096,
		MaxGoroutines: int32(maxWorkers) * 2,
		MaxExecutions: int64(cfg.Scan.MaxIterations * maxWorkers),
		MaxBrowserOps: 100,
	}
	governor := resruntime.New(govCfg)

	// Create safety mode manager - default to safe mode
	safetyMgr := safety.NewSafetyModeManager(safety.SafeMode)

	// Create unified policy engine
	controlCfg := control.GovernorConfig{
		MaxTokens:     govCfg.MaxTokens,
		MaxMemoryMB:   govCfg.MaxMemoryMB,
		MaxGoroutines: govCfg.MaxGoroutines,
		MaxExecutions: govCfg.MaxExecutions,
		MaxDepth:      100,
		MaxAgents:     maxWorkers,
	}
	ctrlEngine := control.NewPolicyEngine(controlCfg)

	ticketMgr := ticketing.NewTicketManager()
	for id, pCfg := range cfg.Ticketing.Providers {
		ticketMgr.AddProvider(id, &ticketing.TicketConfig{
			Provider:  ticketing.Provider(pCfg.Provider),
			URL:       pCfg.URL,
			Token:     pCfg.Token.Plain(),
			Email:     pCfg.Email,
			Project:   pCfg.Project,
			Enabled:   pCfg.Enabled,
			Assignees: pCfg.Assignees,
			Owner:     pCfg.Owner,
			Repo:      pCfg.Repo,
			Labels:    pCfg.Labels,
		})
	}

	bountyMgr := bounty.NewManager()

	logger.Info("Bounty manager initialized", logger.Fields{"component": "Coordinator", "platform_count": len(bountyMgr.ListConfigs())})

	var siemCli *siem.SIEMClient
	if cfg.SIEM.Enabled && cfg.SIEM.Endpoint != "" {
		siemCli = siem.NewSIEMClient(siem.SIEMConfig{
			Type:     cfg.SIEM.Type,
			Endpoint: cfg.SIEM.Endpoint,
			APIKey:   cfg.SIEM.APIKey.Plain(),
			Batch:    cfg.SIEM.FanOut,
		})
		logger.Info("SIEM client initialized", logger.Fields{"component": "Coordinator", "siem_type": cfg.SIEM.Type, "endpoint": cfg.SIEM.Endpoint})
	}

	distOrch := distexec.New(maxWorkers)
	simEng := simulate.New()
	attGraph := graph.New()
	escalQ := escalation.NewQueue()
	oobBase := ""
	if oobSrv != nil {
		oobBase = oobSrv.URLFor("secondorder")
	}
	soEng := secondorder.NewCorrelationEngine(oobBase)

	ttpReg := ttp.NewRegistry()
	logger.Info("TTP registry initialized", logger.Fields{"component": "Coordinator", "playbook_count": len(ttpReg.List())})

	verifEng := verifier.NewEngine()
	logger.Info("Verifier engine initialized", logger.Fields{"component": "Coordinator"})

	confGate := cfg.Scan.ConfidenceGate
	if confGate <= 0 || confGate > 1 {
		confGate = 0.5
	}
	fpFil := validator.NewFPFilter()
	logger.Info("FPFilter initialized", logger.Fields{"component": "Coordinator", "confidence_gate": confGate})

	scoringEng := engine.NewScoringEngine()
	logger.Info("Scoring engine initialized", logger.Fields{"component": "Coordinator"})

	return &Coordinator{
		maxWorkers:         maxWorkers,
		llm:                client,
		outputPath:         outputPath,
		outputFmt:          outputFmt,
		oob:                oobSrv,
		dash:               dash,
		firmName:           "Ares Security",
		evidenceManager:    evidenceManager,
		complianceReporter: complianceReporter,
		c2Manager:          c2Manager,
		maxIterations:      cfg.Scan.MaxIterations,
		scanTimeout:        scanTimeout,
		policyEngine:       ctrlEngine,
		resourceGovernor:   governor,
		safetyMode:         safetyMgr,
		controlEngine:      ctrlEngine,
		webhookManager:     whManager,
		ticketManager:      ticketMgr,
		bountyManager:      bountyMgr,
		siemClient:         siemCli,
		distOrch:           distOrch,
		simEng:             simEng,
		graph:              attGraph,
		escalationQueue:    escalQ,
		secondOrderEng:     soEng,
		rateLimit:          cfg.Scan.RateLimit,
		rateBurst:          cfg.Scan.RateBurst,
		ttpRegistry:        ttpReg,
		verifierEngine:     verifEng,
		scoringEngine:      scoringEng,
		confidenceGate:     confGate,
		fpFilter:           fpFil,
		scanControls:       &ScanControls{agents: make(map[string]*agent.Agent)},
		cancelFuncs:        make(map[string][]context.CancelFunc),
	}
}

func (c *Coordinator) Run(target string) error {
	return c.RunWithResume(target, nil)
}

func (c *Coordinator) RunWithResume(target string, checkpoint *persistence.Checkpoint) error {
	traceID := otel.NewTraceID()
	span := otel.StartSpan(traceID, "", "coordinator.run")
	otel.SetAttribute(span, "target", target)
	defer otel.EndSpan(span)

	sc := scope.NewScope(target)
	targets := []string{target}

	sanitizedTarget, err := security.SanitizeFilename(target)
	if err != nil || sanitizedTarget == "" {
		sanitizedTarget = "unknown"
	}
	auditPath := fmt.Sprintf("%s_%s.audit.jsonl", c.outputPath, sanitizedTarget)
	trail, err := audit.New(target, auditPath)
	if err != nil {
		logger.Warn("Audit trail unavailable", logger.Fields{"component": "Coordinator", "error": err})
	}

	runCtx, cancel := context.WithTimeout(context.Background(), c.scanTimeout)
	defer cancel()

	resumePhase := ""
	resumeIteration := 0
	if checkpoint != nil && checkpoint.Phase != "" && checkpoint.Phase != "completed" && checkpoint.Phase != "shutdown" {
		resumePhase = checkpoint.Phase
		resumeIteration = checkpoint.Iteration
		logger.Info("Resuming scan from checkpoint", logger.Fields{
			"component": "Coordinator",
			"phase":     resumePhase,
			"iteration": resumeIteration,
		})
	} else {
		c.mu.RLock()
		storedCheckpoint := c.resumeCheckpoint
		c.mu.RUnlock()
		if storedCheckpoint != nil && storedCheckpoint.Phase != "" && storedCheckpoint.Phase != "completed" && storedCheckpoint.Phase != "shutdown" {
			resumePhase = storedCheckpoint.Phase
			resumeIteration = storedCheckpoint.Iteration
			logger.Info("Resuming scan from stored checkpoint", logger.Fields{
				"component": "Coordinator",
				"phase":     resumePhase,
				"iteration": resumeIteration,
			})
		}
	}

	c.push(target, "SCAN_START", fmt.Sprintf("Scan started: %s | scope: %s", target, sc.Summary()))
	c.reportProgress(target, "running", "", 0, target)
	if resumePhase != "" {
		c.push(target, "SCAN_RESUME", fmt.Sprintf("Resuming from phase: %s (iteration %d)", resumePhase, resumeIteration))
	}
	if c.discordWebhook != nil {
		go func() {
			if err := c.discordWebhook.SendScanStatus(target, "started", 0); err != nil {
				logger.Error("Discord webhook failed", logger.Fields{"component": "Coordinator", "error": err})
			}
		}()
	}
	if trail != nil {
		trail.Log(audit.EventScanStart, "", "", "", "Scan started")
	}

	bountyReports := c.bountyManager.MatchTarget(target)
	if len(bountyReports) > 0 {
		logger.Info("Existing bounty reports match target", logger.Fields{"component": "Coordinator", "report_count": len(bountyReports), "target": target})
		c.push(target, "BOUNTY_CHECK", fmt.Sprintf("Found %d bounty reports for target", len(bountyReports)))
		for _, br := range bountyReports {
			logger.Info("Matching bounty report", logger.Fields{"component": "Coordinator", "platform": br.Provenance.Platform, "title": br.Report.Title, "severity": br.Severity, "researcher": br.Provenance.Researcher})
		}
	}

	// Capture the current external scan ID so worker cancel funcs can be looked up
	extScanID, _ := c.externalScanID.Load().(string)

	sem := make(chan struct{}, c.maxWorkers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allContexts := make([]*agent.ScanContext, 0)

	var trailMu sync.Mutex

	// Start specialized scanners in background so findings appear progressively during the agent loop
	specCtx := context.Background()
	oobDomain := ""
	if c.oob != nil {
		oobDomain = c.oob.URLFor(target)
	}
	var specWg sync.WaitGroup
	specWg.Add(1)
	go c.runScannersConcurrent(specCtx, target, oobDomain, &allContexts, &mu, &specWg)

	for i, t := range targets {
		sem <- struct{}{} // acquire before spawning goroutine
		wg.Add(1)

		go func(idx int, tgt string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Worker panic", logger.Fields{"component": "Coordinator", "panic": r})
				}
			}()

			select {
			case <-runCtx.Done():
				return
			default:
			}

			scanID := fmt.Sprintf("ARES-%s-%d", tgt, idx)

			c.mu.RLock()
			tenantMgr := c.tenantManager
			scanCtr := c.scanCounter
			c.mu.RUnlock()

			if err := c.checkTenantQuotaWith(tenantMgr, scanCtr, "default"); err != nil {
				logger.Error("Tenant quota exceeded", logger.Fields{"component": "Coordinator", "error": err})
				c.push(scanID, "SCAN_QUOTA", fmt.Sprintf("Scan blocked: %v", err))
				return
			}
			c.recordScanWith(scanCtr, "default")

			trace := telemetry.New(scanID, tgt)
			sc2 := agent.NewScanContext(scanID, tgt)
			sc2.Trace = trace

			if extID, ok := c.externalScanID.Load().(string); ok && extID != "" {
				if creds, ok := c.externalScanCredentials.Load(extID); ok {
					if cs, ok := creds.(*scanctx.CredentialSet); ok && cs != nil {
						sc2.Credentials = cs
					}
				}
			}

			sc2.OnFinding = func(f agent.Finding) {
				cbScanID := scanID
				if extID, ok := c.externalScanID.Load().(string); ok && extID != "" {
					cbScanID = extID
				}
				if c.findingCallback != nil {
					c.findingCallback(cbScanID, f)
				}
				c.push(scanID, "FINDING_ADD", fmt.Sprintf("[%s] %s @ %s (confirmed=%v)", f.Severity, f.Title, f.Endpoint, f.Confirmed))
			}

			mu.Lock()
			allContexts = append(allContexts, sc2)
			mu.Unlock()

			var oobURL string
			if c.oob != nil {
				oobURL = c.oob.URLFor(scanID)
			}
			extra := scanner.SystemPromptHints(tgt, oobURL)

			cves := cve.CorrelateString(tgt)
			extra += cve.SystemPromptSection(cves)

			extra += federated.SystemPromptSection(tgt, "web")

			if c.apiMap != nil {
				extra += c.apiMap.SystemPromptSection()
			}

			c.push(scanID, "SCAN_START", fmt.Sprintf("Worker %d starting: %s", idx, tgt))

			var loop *agent.Loop
			clientForAgent := c.clientForAgent()
			if c.c2Manager != nil {
				c2Client, ok := c.c2Manager.GetClient("sliver")
				if !ok {
					logger.Error("[Coordinator] Failed to get C2 client")
				}
				if c2Client != nil {
					loop = agent.NewLoopWithC2(sc2, clientForAgent, extra, c2Client)
				}
			}
			if loop == nil {
				loop = agent.NewLoop(sc2, clientForAgent, extra)
			}

			loop.Agent.SetPolicyEngine(c.controlEngine)
			loop.Agent.SetResourceGovernor(c.resourceGovernor)
			loop.Agent.SetSafetyModeManager(c.safetyMode)

			c.mu.RLock()
			sqliteMem := c.sqliteMem
			c.mu.RUnlock()
			if sqliteMem != nil {
				loop.Agent.SetSQLiteMemory(sqliteMem)
			}
			if c.rateLimit > 0 && c.rateBurst > 0 {
				loop.Agent.SetRateLimit(c.rateLimit, c.rateBurst)
			}
			loop.Agent.EnsureTools()
			if resumePhase != "" {
				pm := loop.Agent.GetPhaseManager()
				if pm != nil {
					pm.ResumeFromPhase(resumePhase)
				}
			}
			c.mu.RLock()
			selectedPhases := c.selectedPhases
			c.mu.RUnlock()
			if len(selectedPhases) > 0 {
				pm := loop.Agent.GetPhaseManager()
				if pm != nil {
					pm.SetSelectedPhases(selectedPhases)
				}
			}

			pm := loop.Agent.GetPhaseManager()
			if pm != nil {
				scanIDForCallback := scanID
				pushFn := c.push
				pm.SetOnPhaseChange(func(oldPhase, newPhase scanctx.Phase22) {
					if newPhase != "" {
						pushFn(scanIDForCallback, "phase_change", fmt.Sprintf("Phase advanced to: %s", newPhase))
						c.reportProgress(scanIDForCallback, "running", string(newPhase), pm.Progress(), tgt)
					}
				})

				currentPhase := pm.CurrentPhaseID()
				if currentPhase != "" {
					pushFn(scanID, "phase_change", fmt.Sprintf("Starting phase: %s", currentPhase))
					c.reportProgress(scanID, "running", string(currentPhase), pm.Progress(), tgt)
				}

				loop.Agent.SetProgressCallback(func(iteration int, phase string, progress float64) {
					c.reportProgress(scanIDForCallback, "running", phase, progress, tgt)
				})
			}
			c.mu.RLock()
			sc := c.scanControls
			c.mu.RUnlock()
			if sc != nil {
				sc.Register(scanID, loop.Agent)
				defer sc.Unregister(scanID)
			}

			workerCtx, workerCancel := context.WithCancel(runCtx)
			if extScanID != "" {
				c.cancelFuncsMu.Lock()
				c.cancelFuncs[extScanID] = append(c.cancelFuncs[extScanID], workerCancel)
				c.cancelFuncsMu.Unlock()
			}
			defer func() {
				if extScanID != "" {
					c.cancelFuncsMu.Lock()
					delete(c.cancelFuncs, extScanID)
					c.cancelFuncsMu.Unlock()
				}
				workerCancel()
			}()

			workerSpan := otel.StartSpan(traceID, span.SpanID, "coordinator.worker")
			otel.SetAttribute(workerSpan, "scan_id", scanID)
			otel.SetAttribute(workerSpan, "target", tgt)
			defer otel.EndSpan(workerSpan)

			runErr := loop.RunWithContext(workerCtx, c.maxIterations)
			if runErr != nil {
				logger.Error("Worker error", logger.Fields{"component": "Coordinator", "worker_index": idx, "error": runErr})
				c.push(scanID, "SCAN_END", fmt.Sprintf("Worker error: %v", runErr))
			} else {
				c.push(scanID, "SCAN_END", fmt.Sprintf("Agent loop complete: %d confirmed findings", sc2.ConfirmedCount()))
			}

			// Save checkpoint after scan (graceful shutdown recovery)
			if c.checkpointStore != nil {
				cp := persistence.Checkpoint{
					ID:        scanID,
					Timestamp: time.Now(),
					Phase:     "completed",
					Iteration: loop.Agent.Iteration(),
					Targets:   []string{tgt},
					Findings:  sc2.ConfirmedFindings,
				}
				if runErr != nil {
					cp.Phase = "interrupted"
				}
				if err := c.checkpointStore.Save(cp); err != nil {
					logger.Warn("Failed to save checkpoint", logger.Fields{"component": "Coordinator", "scan_id": scanID, "error": err})
				}
			}

			for i := range sc2.ConfirmedFindings {
				c.processFinding(scanID, tgt, &sc2.ConfirmedFindings[i], trail, &trailMu)
			}
			for i := range sc2.UnverifiedFindings {
				c.processFinding(scanID, tgt, &sc2.UnverifiedFindings[i], trail, &trailMu)
			}
		}(i, t)
	}

	wg.Wait()

	if trail != nil {
		trail.Close()
	}

	// Get the effective scan ID for findings processing (external ID for web store)
	effectiveScanID := target
	if extID, ok := c.externalScanID.Load().(string); ok && extID != "" {
		effectiveScanID = extID
	}

	// Wait for specialized scanners to complete (started concurrently with agent loop above)
	specWg.Wait()

	// Process all findings (both confirmed and unverified) through the pipeline.
	// We iterate by index with pointers so the verifier/FP-filter modifications
	// propagate back into the scan context. All workers have completed at this
	// point (wg.Wait() above), so no concurrent access occurs.
	if len(allContexts) > 0 && allContexts[0] != nil {
		for i := 0; i < len(allContexts[0].ConfirmedFindings); i++ {
			c.processFinding(effectiveScanID, target, &allContexts[0].ConfirmedFindings[i], trail, &trailMu)
		}
		for i := 0; i < len(allContexts[0].UnverifiedFindings); i++ {
			c.processFinding(effectiveScanID, target, &allContexts[0].UnverifiedFindings[i], trail, &trailMu)
		}
	}

	merged := c.merge(allContexts, target)
	c.push(target, "SCAN_END", fmt.Sprintf("Report generating: %d total findings", merged.ConfirmedCount()))
	if c.discordWebhook != nil {
		go func() {
			if err := c.discordWebhook.SendScanStatus(target, "completed", merged.ConfirmedCount()); err != nil {
				logger.Error("Discord webhook failed", logger.Fields{"component": "Coordinator", "error": err})
			}
		}()
	}

	// Build attack graph from confirmed findings
	targetNode := fmt.Sprintf("target-%s", target)
	c.graph.AddNode(targetNode, graph.NodeAsset, target)
	for _, f := range merged.ConfirmedFindings {
		findingNode := fmt.Sprintf("finding-%s", f.ID)
		c.graph.AddNode(findingNode, graph.NodeVuln, f.Title)
		c.graph.AddEdge(targetNode, findingNode, graph.EdgeExploits)
		c.graph.SetNodeProperty(findingNode, "severity", string(f.Severity))
		c.graph.SetNodeProperty(findingNode, "confidence", f.Confidence)
		c.graph.UpdateNodeScore(findingNode, f.Confidence)

		// Submit distexec task for heavy scan payloads
		if f.PoCCode != "" || f.ExtractionProof != "" {
			task := &distexec.Task{
				ID:       fmt.Sprintf("verify-%s", f.ID),
				Type:     "verify",
				Target:   target,
				Priority: c.severityToPriority(f.Severity),
				Payload: map[string]interface{}{
					"finding_id": f.ID,
					"poc":        f.PoCCode,
					"evidence":   f.ExtractionProof,
				},
			}
			if err := c.distOrch.Submit(task); err != nil {
				logger.Error("distexec submit failed", logger.Fields{"component": "Coordinator", "error": err})
			}
		}

		// Check escalation conditions
		if f.Severity == agent.Critical || (f.Confidence >= 0.7 && f.Confidence < 0.95 && f.ExtractionProof != "") {
			nf := escalation.BuildEscalation(target, f.Endpoint, f.MITRETechnique, f.Confidence, f.ExtractionProof, string(f.Severity))
			nf.ID = f.ID
			nf.Title = f.Title
			c.escalationQueue.Add(nf)
		}
	}

	// Persist attack graph to disk
	graphPath := fmt.Sprintf("%s_attack_graph.json", c.outputPath)
	persist, err := graph.NewPersist(graphPath)
	if err != nil {
		logger.Warn("Failed to create attack graph persist", logger.Fields{"component": "Coordinator", "error": err})
	} else {
		if err := persist.Save(c.graph); err != nil {
			logger.Warn("Failed to persist attack graph", logger.Fields{"component": "Coordinator", "error": err})
		} else {
			logger.Info("Attack graph persisted", logger.Fields{"component": "Coordinator", "path": graphPath})
		}
	}

	// Run attack chain analysis
	chains := c.graph.FindChains(targetNode, "", 5)
	if len(chains) > 0 {
		logger.Info("Found attack chains", logger.Fields{"component": "Coordinator", "chain_count": len(chains)})
		for _, chain := range chains {
			logger.Info("Attack chain", logger.Fields{"component": "Coordinator", "summary": chain.Summary, "score": chain.Score})
			c.push(target, "CHAIN_FOUND", fmt.Sprintf("Attack chain: %s (score: %.2f)", chain.Summary, chain.Score))
		}
	}

	suggestions := c.graph.SuggestNextTargets(targetNode, 0.5)
	if len(suggestions) > 0 {
		logger.Info("Suggested next targets", logger.Fields{"component": "Coordinator", "node_count": len(suggestions)})
	}

	// Register second-order correlation for confirmed findings
	if c.secondOrderEng != nil {
		for _, f := range merged.ConfirmedFindings {
			if _, err := c.secondOrderEng.GenerateToken(); err != nil {
				logger.Error(fmt.Sprintf("Failed to generate second-order token: %v", err))
				continue
			}
			logger.Info("Second-order token generated", logger.Fields{"component": "Coordinator", "token": "[REDACTED]", "finding_id": f.ID})
		}
	}

	// Run simulation campaign based on findings
	if c.simEng != nil && len(merged.ConfirmedFindings) > 0 {
		criticals := 0
		for _, f := range merged.ConfirmedFindings {
			if f.Severity == agent.Critical {
				criticals++
			}
		}
		if criticals > 0 {
			actorName := "APT29"
			if len(c.simEng.Actors()) > 0 {
				actorName = c.simEng.Actors()[0].Name
			}
			campaign := c.simEng.RunCampaign(target, actorName)
			if campaign != nil {
				logger.Info("Simulation campaign", logger.Fields{"component": "Coordinator", "campaign": campaign.Name, "score": campaign.Score, "actor": campaign.Actor.Name})
				c.push(target, "SIMULATION", fmt.Sprintf("Campaign: %s matched (actor: %s)", campaign.Name, campaign.Actor.Name))
			}
		}
	}

	// Attempt C2 handoff if manager is configured
	if c.c2Manager != nil && c.c2Manager.IsConnected() {
		session := c.c2Manager.AttemptC2Handoff(runCtx, target, 0)
		if session != nil {
			logger.Info("C2 session established", logger.Fields{"component": "Coordinator", "session_id": "[REDACTED]"})
			c.push(target, "C2_HANDOFF", "C2 session established")
		}
	}

	// Apply confidence gate — filter out low-confidence findings before report
	filtered := make([]agent.Finding, 0, len(merged.ConfirmedFindings))
	for _, f := range merged.ConfirmedFindings {
		if f.Confidence >= c.confidenceGate {
			filtered = append(filtered, f)
		} else {
			logger.Debug("Finding filtered by confidence gate", logger.Fields{
				"component":  "Coordinator",
				"finding_id": f.ID,
				"title":      f.Title,
				"confidence": f.Confidence,
				"gate":       c.confidenceGate,
			})
		}
	}
	merged.ConfirmedFindings = filtered

	if c.webhookManager != nil {
		summary := c.buildScanSummary(target, merged)
		c.webhookManager.DispatchScanComplete(summary.ScanID, target, summary)
	}

	if err := report.GenerateWithFormat(merged, c.firmName, c.outputPath, report.OutputFormat(c.outputFmt)); err != nil {
		return fmt.Errorf("failed to generate standard report: %w", err)
	}

	// SARIF report generation
	sarifGen := sarif.NewGenerator("ARES-Engine", "2.0.0")
	for _, f := range merged.ConfirmedFindings {
		sarifGen.AddFinding(sarif.Finding{
			ID:             f.ID,
			Type:           string(f.MITRETechnique),
			Severity:       string(f.Severity),
			Target:         f.Endpoint,
			Payload:        f.PoCCode,
			Evidence:       f.ExtractionProof,
			Confidence:     f.Confidence,
			Remediation:    report.LookupRemediation(f.Title, f.Description),
			CWE:            f.CWEID,
			CVE:            f.CVEID,
			Timestamp:      f.Timestamp,
			Classification: sarif.ClassificationVulnerability,
		})
	}
	sarifData, err := sarifGen.Generate()
	if err != nil {
		logger.Warn("Failed to generate SARIF report", logger.Fields{"component": "Coordinator", "error": err})
	} else {
		sarifPath := c.outputPath + "_report.sarif"
		if err := os.WriteFile(sarifPath, sarifData, 0600); err != nil {
			logger.Warn("Failed to write SARIF report", logger.Fields{"component": "Coordinator", "path": sarifPath, "error": err})
		} else {
			logger.Info("SARIF report written", logger.Fields{"component": "Coordinator", "path": sarifPath, "findings": len(merged.ConfirmedFindings)})
		}
	}

	frameworks := []compliance.ComplianceFramework{
		compliance.FrameworkNIST80053,
		compliance.FrameworkISO27001,
		compliance.FrameworkPCIDSS,
		compliance.FrameworkSOC2,
		compliance.FrameworkHIPAA,
		compliance.FrameworkGDPR,
	}

	for _, framework := range frameworks {
		complianceReport := c.complianceReporter.GenerateReport(target, framework)
		if complianceReport != nil && len(complianceReport.Mappings) > 0 {
			compliancePath := fmt.Sprintf("%s_compliance_%s.json", c.outputPath, string(framework))
			data, err := json.MarshalIndent(complianceReport, "", "  ")
			if err != nil {
				logger.Error("Failed to marshal compliance report", logger.Fields{"component": "Coordinator", "framework": framework, "error": err})
				continue
			}
			if err := os.WriteFile(compliancePath, data, 0600); err != nil {
				logger.Error("Failed to write compliance report", logger.Fields{"component": "Coordinator", "framework": framework, "error": err})
				continue
			}
		}
	}

	c.persistGraph()
	c.reportProgress(target, "completed", "done", 1.0, target)

	return nil
}

func (c *Coordinator) processFinding(scanID, tgt string, f *agent.Finding, trail *audit.AuditTrail, trailMu *sync.Mutex) {
	if c.fpFilter != nil {
		fpArgs := &validator.ReportArgs{
			Title:             f.Title,
			Description:       f.Description,
			Severity:          string(f.Severity),
			ExploitationProof: f.ExtractionProof,
			Response:          f.ExtractionProof,
			Payload:           f.PoCCode,
		}
		fpResult := c.fpFilter.Filter(fpArgs)
		if fpResult.Verdict == validator.VerdictFalsePositive {
			logger.Info("FP filter rejected finding", logger.Fields{
				"component":  "Coordinator",
				"finding_id": f.ID,
				"title":      f.Title,
				"reason":     fpResult.Reason,
			})
			c.push(scanID, "FINDING_REJECTED", fmt.Sprintf("FP filter: %s (%s)", f.Title, fpResult.Reason))
			return
		}
		if fpResult.Verdict == validator.VerdictSuspected {
			logger.Info("FP filter marked as suspected", logger.Fields{
				"component":  "Coordinator",
				"finding_id": f.ID,
				"title":      f.Title,
				"reason":     fpResult.Reason,
			})
		}
	}

	if c.ttpRegistry != nil {
		ttpClass := c.mapFindingToTTPClass(f.Title)
		if ttpClass != "" {
			evidence := make(map[string]string)
			if f.PoCCode != "" {
				evidence["payload"] = f.PoCCode
			}
			if f.ExtractionProof != "" {
				evidence["extraction_proof"] = f.ExtractionProof
			}
			if f.Endpoint != "" {
				evidence["endpoint"] = f.Endpoint
			}
			result := c.ttpRegistry.Verify(ttpClass, tgt, evidence)
			if result != nil && result.Confirmed {
				f.Confirmed = true
				f.Confidence = result.Confidence
				if result.CVSSScore > 0 {
					f.CVSSScore = result.CVSSScore
				}
				if result.Reproduction != "" {
					f.PoCSteps = append(f.PoCSteps, result.Reproduction)
				}
				logger.Info("TTP verification confirmed", logger.Fields{
					"component":  "Coordinator",
					"finding_id": f.ID,
					"vuln_class": ttpClass,
					"confidence": result.Confidence,
					"tool_used":  result.ToolUsed,
				})
			} else if result != nil {
				logger.Info("TTP verification not confirmed", logger.Fields{
					"component":  "Coordinator",
					"finding_id": f.ID,
					"vuln_class": ttpClass,
					"evidence":   result.Evidence,
				})
			}
		}
	}

	if c.verifierEngine != nil {
		verifMethod := c.inferVerifierMethod(f.Title, *f)
		if verifMethod != "" {
			verifReq := verifier.VerificationRequest{
				ID:       f.ID,
				VulnType: f.Title,
				Target:   tgt,
				Payload:  f.PoCCode,
				Method:   verifMethod,
			}
			if f.ExtractionProof != "" {
				verifReq.ExpectedOutput = f.ExtractionProof
			}
			verifResult := c.verifierEngine.Verify(verifReq)
			if verifResult.Verdict == verifier.VerdictConfirmed {
				f.Confirmed = true
				f.Confidence = verifResult.Confidence
				logger.Info("Deterministic verifier confirmed", logger.Fields{
					"component":  "Coordinator",
					"finding_id": f.ID,
					"method":     string(verifMethod),
					"confidence": verifResult.Confidence,
				})
			}
		}
	}

	if c.scoringEngine != nil && f.CVSSVector == "" {
		f.CVSSVector = c.scoringEngine.GenerateCVSSVector(string(f.Severity), f.Title, f.Confirmed)
		if f.CVSSScore <= 0 && f.CVSSVector != "" {
			f.CVSSScore = c.scoringEngine.CVSSScoreFromVector(f.CVSSVector)
		}
	}

	// Use the effective scan ID for the finding callback so findings are stored
	// under the correct scan session in the web ScanStore.
	callbackScanID := scanID
	if extID, ok := c.externalScanID.Load().(string); ok && extID != "" {
		callbackScanID = extID
	}
	c.push(scanID, "FINDING_ADD", fmt.Sprintf("[%s] %s @ %s (confirmed=%v)", f.Severity, f.Title, f.Endpoint, f.Confirmed))
	if c.findingCallback != nil {
		c.findingCallback(callbackScanID, *f)
	}
	if trail != nil {
		trailMu.Lock()
		trail.LogFinding(f.ID, f.Title, string(f.Severity))
		trailMu.Unlock()
	}
	c.processFindingWithEvidence(scanID, tgt, *f)

	if c.webhookManager != nil {
		payload := webhook.FindingPayload{
			ScanID:      scanID,
			Target:      tgt,
			ID:          f.ID,
			Title:       f.Title,
			Severity:    string(f.Severity),
			Description: f.Description,
			CVSS:        f.CVSSScore,
			Endpoint:    f.Endpoint,
			Timestamp:   f.Timestamp.Format(time.RFC3339),
		}
		c.webhookManager.DispatchFindingCreated(scanID, tgt, payload)

		if f.Severity == agent.Critical {
			c.webhookManager.DispatchCriticalAlert(scanID, tgt, payload)
		}
	}

	if c.siemClient != nil {
		ctx := context.Background()
		event := siem.SIEMEvent{
			EventType:  "report_vulnerability",
			Severity:   string(f.Severity),
			Target:     tgt,
			VulnType:   f.Title,
			Payload:    f.PoCCode,
			Evidence:   f.ExtractionProof,
			Confidence: f.Confidence,
			ScanID:     scanID,
			Metadata: map[string]string{
				"finding_id":      f.ID,
				"mitre_technique": f.MITRETechnique,
				"endpoint":        f.Endpoint,
				"cef_severity":    fmt.Sprintf("%d", severityToCEF(string(f.Severity))),
			},
		}
		if err := c.siemClient.Push(ctx, event); err != nil {
			logger.Error("SIEM push failed for finding", logger.Fields{"component": "Coordinator", "finding_id": f.ID, "error": err})
		}
	}

	if c.discordWebhook != nil {
		go func() {
			err := c.discordWebhook.SendFinding(tgt, f.Title, string(f.Severity), f.Description)
			if err != nil {
				logger.Error("Discord webhook failed", logger.Fields{"component": "Coordinator", "finding_id": f.ID, "error": err})
			}
		}()
	}

	if c.bountyManager != nil {
		if matched := c.bountyManager.MatchFinding(f.Title, f.Description); matched != nil {
			logger.Info("Finding matches bounty report", logger.Fields{"component": "Coordinator", "finding_id": f.ID, "report_id": matched.ID, "report_title": matched.Report.Title})
			c.push(scanID, "BOUNTY_MATCH",
				fmt.Sprintf("Finding matches bounty report: %s (platform: %s, researcher: %s)",
					matched.Report.Title, matched.Provenance.Platform, matched.Provenance.Researcher))
			c.bountyManager.UpdateReportStatus(matched.ID, "verified", f.ID)
		}
	}

	if c.ticketManager != nil && (f.Severity == agent.Critical || f.Severity == agent.High) {
		evidence := make(map[string]string)
		if f.ExtractionProof != "" {
			evidence["extraction_proof"] = f.ExtractionProof
		}
		if f.PoCCode != "" {
			evidence["poc_code"] = f.PoCCode
		}
		c.ticketManager.CreateFindingTicket(scanID, tgt, ticketing.FindingInfo{
			ID:          f.ID,
			Title:       f.Title,
			Severity:    string(f.Severity),
			Target:      tgt,
			Description: f.Description,
			Evidence:    evidence,
			CVSS:        f.CVSSScore,
			Type:        f.MITRETechnique,
		})
	}
}

func (c *Coordinator) SetScanProgressFn(fn ScanProgressFn) {
	c.mu.Lock()
	c.progressFn = fn
	c.mu.Unlock()
}

func (c *Coordinator) SetFindingCallbackFn(fn FindingCallbackFn) {
	c.mu.Lock()
	c.findingCallback = fn
	c.mu.Unlock()
}

func (c *Coordinator) SetEventCallbackFn(fn EventCallbackFn) {
	c.mu.Lock()
	c.eventCallback = fn
	c.mu.Unlock()
}

func (c *Coordinator) SetExternalScanID(id string) {
	c.externalScanID.Store(id)
}

func (c *Coordinator) clientForAgent() llm.LLMClient {
	c.mu.RLock()
	primary := c.llmPrimary
	fallback := c.llmFallback
	local := c.llmLocal
	router := c.llmRouter
	c.mu.RUnlock()

	if primary == nil {
		primary = c.llm
	}
	if primary == nil {
		return nil
	}
	if fallback == nil && local == nil {
		return primary
	}
	return llmrouting.NewFallbackClient(primary, fallback, local, router)
}

func (c *Coordinator) SetSQLiteMemory(sm *huntmemory.SQLiteMemory) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sqliteMem = sm
}

func (c *Coordinator) SetLLMBackends(primary *llm.Client, fallback, local llm.LLMClient, router *llmrouting.Router) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.llm = primary
	c.llmPrimary = primary
	c.llmFallback = fallback
	c.llmLocal = local
	if router != nil {
		c.llmRouter = router
	}
}

func (c *Coordinator) SetExternalCredentials(id string, creds *scanctx.CredentialSet) {
	if creds != nil {
		c.externalScanCredentials.Store(id, creds)
	}
}

func (c *Coordinator) SetCheckpointDir(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkpointDir = dir
	c.checkpointStore = persistence.NewDiskStore(dir, 50)
}

func (c *Coordinator) ScanControls() *ScanControls {
	return c.scanControls
}

// CancelScan cancels any running workers for the given external scan ID.
// The workers check ctx.Done() at each iteration and will exit promptly.
func (c *Coordinator) CancelScan(scanID string) {
	c.cancelFuncsMu.Lock()
	cancelFuncs := c.cancelFuncs[scanID]
	delete(c.cancelFuncs, scanID)
	c.cancelFuncsMu.Unlock()
	for _, cancel := range cancelFuncs {
		cancel()
	}
}

func (c *Coordinator) reportProgress(scanID, status, phase string, progress float64, target string) {
	if extID, ok := c.externalScanID.Load().(string); ok && extID != "" {
		scanID = extID
	}
	if c.progressFn != nil {
		c.progressFn(scanID, status, phase, progress, target)
	}
}

func (c *Coordinator) push(scanID, evType, msg string) {
	if extID, ok := c.externalScanID.Load().(string); ok && extID != "" {
		scanID = extID
	}
	if c.dash != nil {
		c.dash.Push(scanID, evType, msg)
	}
	if c.eventCallback != nil {
		c.eventCallback(scanID, evType, msg)
	}
	logger.Info("Event push", logger.Fields{"component": "Coordinator", "scan_id": scanID, "event_type": evType, "message": msg})
}

func (c *Coordinator) mapFindingToEvidenceType(title string) evidence.EvidenceType {
	lower := strings.ToLower(title)
	switch {
	case strings.Contains(lower, "sql") || strings.Contains(lower, "injection"):
		return evidence.EvidenceTypeDatabaseInfo
	case strings.Contains(lower, "xss") || strings.Contains(lower, "cross-site"):
		return evidence.EvidenceTypeXSSReflection
	case strings.Contains(lower, "file") || strings.Contains(lower, "path") || strings.Contains(lower, "lfi") || strings.Contains(lower, "rfi"):
		return evidence.EvidenceTypeFileContent
	case strings.Contains(lower, "command") || strings.Contains(lower, "rce") || strings.Contains(lower, "execution"):
		return evidence.EvidenceTypeCommandOutput
	case strings.Contains(lower, "network") || strings.Contains(lower, "port") || strings.Contains(lower, "host"):
		return evidence.EvidenceTypeNetworkInfo
	case strings.Contains(lower, "credential") || strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "key"):
		return evidence.EvidenceTypeCredential
	case strings.Contains(lower, "shell") || strings.Contains(lower, "web"):
		return evidence.EvidenceTypeWebShell
	case strings.Contains(lower, "persist") || strings.Contains(lower, "backdoor") || strings.Contains(lower, "rootkit"):
		return evidence.EvidenceTypePersistence
	default:
		return evidence.EvidenceTypeFileContent
	}
}

func (c *Coordinator) mapFindingToTTPClass(title string) string {
	lower := strings.ToLower(title)
	switch {
	case strings.Contains(lower, "sql injection") || strings.Contains(lower, "sqli"):
		return "sqli"
	case strings.Contains(lower, "xss") || strings.Contains(lower, "cross-site scripting"):
		return "xss"
	case strings.Contains(lower, "ssrf") || strings.Contains(lower, "server-side request forgery"):
		return "ssrf"
	case strings.Contains(lower, "rce") || strings.Contains(lower, "remote code execution") || strings.Contains(lower, "command injection"):
		return "rce"
	case strings.Contains(lower, "lfi") || strings.Contains(lower, "local file inclusion") || strings.Contains(lower, "path traversal"):
		return "lfi"
	case strings.Contains(lower, "idor") || strings.Contains(lower, "bola") || strings.Contains(lower, "insecure direct object"):
		return "idor"
	case strings.Contains(lower, "ssti") || strings.Contains(lower, "server-side template") || strings.Contains(lower, "template injection"):
		return "ssti"
	case strings.Contains(lower, "xxe") || strings.Contains(lower, "xml external"):
		return "xxe"
	case strings.Contains(lower, "nosql") || strings.Contains(lower, "nosqli") || strings.Contains(lower, "mongodb injection"):
		return "nosqli"
	case strings.Contains(lower, "smuggling") || strings.Contains(lower, "http request smuggling"):
		return "smuggling"
	case strings.Contains(lower, "prototype pollution"):
		return "prototype_pollution"
	case strings.Contains(lower, "csrf") || strings.Contains(lower, "cross-site request forgery"):
		return "csrf"
	case strings.Contains(lower, "race condition"):
		return "race_conditions"
	case strings.Contains(lower, "deserializ"):
		return "deserialization"
	case strings.Contains(lower, "graphql"):
		return "graphql"
	case strings.Contains(lower, "cors") || strings.Contains(lower, "cross-origin"):
		return "cors"
	case strings.Contains(lower, "jwt") || strings.Contains(lower, "json web token"):
		return "jwt_weak"
	case strings.Contains(lower, "open redirect"):
		return "open_redirect"
	case strings.Contains(lower, "blind sql") || strings.Contains(lower, "blind sqli") || strings.Contains(lower, "boolean-based") || strings.Contains(lower, "time-based sql"):
		return "blind_sqli"
	case strings.Contains(lower, "api abuse") || strings.Contains(lower, "rate limit"):
		return "api_abuse"
	default:
		return ""
	}
}

func (c *Coordinator) inferVerifierMethod(title string, f agent.Finding) verifier.VerificationMethod {
	lower := strings.ToLower(title)
	switch {
	case strings.Contains(lower, "xss") || strings.Contains(lower, "reflection"):
		return verifier.MethodReplay
	case strings.Contains(lower, "credential") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "key"):
		return verifier.MethodExtraction
	case strings.Contains(lower, "blind sql") || strings.Contains(lower, "time-based") || strings.Contains(lower, "sleep"):
		return verifier.MethodTiming
	case strings.Contains(lower, "ssrf") || strings.Contains(lower, "oob") || strings.Contains(lower, "callback") || strings.Contains(lower, "dns"):
		return verifier.MethodOOB
	case strings.Contains(lower, "auth") || strings.Contains(lower, "bypass") || strings.Contains(lower, "access control"):
		return verifier.MethodDiff
	case f.PoCCode != "" && f.ExtractionProof != "":
		return verifier.MethodLogical
	default:
		if f.PoCCode != "" {
			return verifier.MethodReplay
		}
		return ""
	}
}

func (c *Coordinator) processFindingWithEvidence(scanID, tgt string, f agent.Finding) {
	if f.ExtractionProof != "" || f.PoCCode != "" || f.EvidencePath != "" {
		evType := c.mapFindingToEvidenceType(f.Title)
		ev := &evidence.Evidence{
			Type:      evType,
			Target:    tgt,
			Technique: f.Title,
			Payload:   f.PoCCode,
			Data: map[string]interface{}{
				"extraction_proof": f.ExtractionProof,
				"poc_code":         f.PoCCode,
				"evidence_path":    f.EvidencePath,
				"description":      f.Description,
				"impact":           f.Impact,
			},
			CollectedAt: f.Timestamp,
			Source:      "ares_scanner",
			Confidence:  f.Confidence,
			Tags:        []string{f.Title, string(f.Severity)},
			Description: fmt.Sprintf("%s: %s", f.Title, f.Description),
		}

		evID := c.evidenceManager.CollectEvidence(ev)
		logger.Info("Collected evidence for finding", logger.Fields{"component": "Coordinator", "evidence_id": evID, "finding_title": f.Title})
	}

	if f.PoCCode != "" {
		federated.Record(f.PoCCode, tgt, string(f.Severity), true)
	}
}

func (c *Coordinator) buildScanSummary(target string, merged *agent.ScanContext) webhook.ScanSummary {
	summary := webhook.ScanSummary{
		ScanID: merged.ScanID,
		Target: target,
		Status: "completed",
	}
	for _, f := range merged.ConfirmedFindings {
		summary.TotalFindings++
		switch f.Severity {
		case agent.Critical:
			summary.CriticalCount++
		case agent.High:
			summary.HighCount++
		case agent.Medium:
			summary.MediumCount++
		case agent.Low:
			summary.LowCount++
		}
	}
	summary.Duration = time.Since(merged.StartTime).Round(time.Second).String()
	return summary
}

func severityToCEF(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 10
	case "high":
		return 7
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 1
	}
}

func (c *Coordinator) severityToPriority(severity agent.Severity) int {
	switch severity {
	case agent.Critical:
		return 1
	case agent.High:
		return 2
	case agent.Medium:
		return 3
	case agent.Low:
		return 4
	default:
		return 5
	}
}

func (c *Coordinator) merge(contexts []*agent.ScanContext, target string) *agent.ScanContext {
	merged := agent.NewScanContext("ARES-MERGED", target)
	seen := make(map[string]bool)
	for _, sc := range contexts {
		for _, f := range sc.GetFindings() {
			key := f.Title + "|" + f.Endpoint + "|" + string(f.Severity)
			if seen[key] {
				continue
			}
			seen[key] = true
			merged.AddFinding(f)
		}
		merged.AuditLog = append(merged.AuditLog, sc.GetAuditLog()...)
		merged.LiveHosts = append(merged.LiveHosts, sc.GetLiveHosts()...)
		merged.Endpoints = append(merged.Endpoints, sc.GetEndpoints()...)
		merged.Notes = append(merged.Notes, sc.GetNotes()...)
	}
	return merged
}

// SetMaxIterations overrides the default max iterations for the scan loop
func (c *Coordinator) SetMaxIterations(n int) {
	c.maxIterations = n
}

// SetSelectedPhases configures the 22-phase methodology selection for scans
func (c *Coordinator) SetSelectedPhases(phases []string) {
	c.mu.Lock()
	c.selectedPhases = phases
	c.mu.Unlock()
}

func (c *Coordinator) checkTenantQuotaWith(tm *multitenant.TenantManager, sc *multitenant.ScanCounter, tenantID string) error {
	if tm == nil || sc == nil {
		return nil
	}
	tenant, err := tm.Get(tenantID)
	if err != nil {
		return nil
	}
	if !tenant.IsActive {
		return fmt.Errorf("tenant %s is not active", tenantID)
	}
	return sc.CheckQuota(tenantID, tenant.MaxScans)
}

func (c *Coordinator) recordScanWith(sc *multitenant.ScanCounter, tenantID string) {
	if sc != nil {
		sc.Increment(tenantID)
	}
}

func (c *Coordinator) persistGraph() {
	c.mu.RLock()
	gp := c.graphPersist
	ag := c.attackGraph
	c.mu.RUnlock()
	if gp != nil && ag != nil {
		if err := gp.Save(ag); err != nil {
			logger.Warn("Graph persistence failed", logger.Fields{"error": err})
		}
	}
}

func (c *Coordinator) runScannersConcurrent(specCtx context.Context, target, oobDomain string, allContexts *[]*agent.ScanContext, mu *sync.Mutex, specWg *sync.WaitGroup) {
	defer specWg.Done()

	// Wait for at least one scan context to be available
	for {
		mu.Lock()
		available := len(*allContexts) > 0 && (*allContexts)[0] != nil
		mu.Unlock()
		if available {
			break
		}
		select {
		case <-time.After(200 * time.Millisecond):
		case <-specCtx.Done():
			return
		}
	}

	addFinding := func(f agent.Finding) {
		mu.Lock()
		if len(*allContexts) > 0 && (*allContexts)[0] != nil {
			(*allContexts)[0].AddFinding(f)
		}
		mu.Unlock()
	}

	// Specialized scanners
	logger.Info("Starting specialized scanners concurrently", logger.Fields{"component": "Coordinator", "target": target})
	specResults := RunSpecializedScanners(specCtx, target, oobDomain)
	for _, specF := range specResults.Findings {
		addFinding(specF)
	}
	if len(specResults.Errors) > 0 {
		logger.Warn("Specialized scanner errors", logger.Fields{"component": "Coordinator", "errors": specResults.Errors})
	}

	// Business logic testing
	if c.bizlogicEngine != nil {
		logger.Info("Starting business logic testing", logger.Fields{"component": "Coordinator", "target": target})
		bizFindings := c.bizlogicEngine.Run(specCtx)
		for _, bf := range bizFindings {
			addFinding(agent.Finding{
				ID:             bf.ID,
				Title:          bf.Title,
				Severity:       agent.Severity(bf.Severity),
				Description:    bf.Description,
				Endpoint:       bf.Endpoint,
				PoCCode:        bf.PoC,
				Impact:         bf.Impact,
				CVSSScore:      bf.CVSS,
				MITRETechnique: bf.MITRE,
				Timestamp:      bf.Timestamp,
			})
		}
		logger.Info("Business logic testing complete", logger.Fields{"component": "Coordinator", "findings": len(bizFindings)})
	}

	// Authentication/authorization testing
	if c.authflowEngine != nil {
		logger.Info("Starting authentication testing", logger.Fields{"component": "Coordinator", "target": target})
		authFindings := c.authflowEngine.Run(specCtx)
		for _, af := range authFindings {
			addFinding(agent.Finding{
				ID:             af.ID,
				Title:          af.Title,
				Severity:       agent.Severity(af.Severity),
				Description:    af.Description,
				Endpoint:       af.Endpoint,
				PoCCode:        af.PoC,
				Impact:         af.Impact,
				CVSSScore:      af.CVSS,
				MITRETechnique: af.MITRE,
				Timestamp:      af.Timestamp,
			})
		}
		logger.Info("Authentication testing complete", logger.Fields{"component": "Coordinator", "findings": len(authFindings)})
	}

	logger.Info("Specialized scanners completed concurrently", logger.Fields{"component": "Coordinator", "target": target})
}
