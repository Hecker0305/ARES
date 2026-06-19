package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/uuid"
	"github.com/ares/engine/internal/agentdeploy"
	"github.com/ares/engine/internal/airgap"
	"github.com/ares/engine/internal/exposure"
	"github.com/ares/engine/internal/approvals"
	"github.com/ares/engine/internal/knowledgegraph"
	"github.com/ares/engine/internal/validationloop"
	"github.com/ares/engine/internal/verifier"
	"github.com/ares/engine/internal/purpleteam"
	"github.com/ares/engine/internal/copilot"
	"github.com/ares/engine/internal/asm"
	"github.com/ares/engine/internal/compliancebuilder"
	"github.com/ares/engine/internal/collaboration"
	"github.com/ares/engine/internal/pythondaemon"
	"github.com/ares/engine/internal/ransomware"
	"github.com/ares/engine/internal/packetinjection"
	"github.com/ares/engine/internal/netsim"
	"github.com/ares/engine/internal/apikey"
	"github.com/ares/engine/internal/redteam"
	"github.com/ares/engine/internal/audit"
	"github.com/ares/engine/internal/auth"
	"github.com/ares/engine/internal/cloudscanner"
	"github.com/ares/engine/internal/coderemediation"
	"github.com/ares/engine/internal/evidence"
	"github.com/ares/engine/internal/graph"
	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/metrics"
	"github.com/ares/engine/internal/secrets"
	"github.com/ares/engine/internal/config"
	"github.com/ares/engine/internal/report"
	"github.com/ares/engine/internal/security"
	"github.com/ares/engine/internal/store"
	"github.com/ares/engine/internal/attackpath"
	"github.com/ares/engine/internal/bounty"
	"github.com/ares/engine/internal/risk"
	"github.com/ares/engine/internal/saml"
	"github.com/ares/engine/internal/scheduler"
	"github.com/ares/engine/internal/web/ratelimit"
	"github.com/ares/engine/internal/webserver"
	"github.com/ares/engine/internal/webserver/frontend"
	"github.com/ares/engine/internal/websocket"
	"github.com/ares/engine/internal/worker"
)

type ServerConfig struct {
	Port          int
	TLS           bool
	CertFile      string
	KeyFile       string
	SessionSecret string
	CORSOrigins   []string
	RateLimit     int
	StaticDir     string
	StoreDir      string
}

type ScanSession struct {
	mu          sync.RWMutex
	ID          string            `json:"id"`
	Target      string            `json:"target"`
	StartTime   time.Time         `json:"start_time"`
	Status      string            `json:"status"`
	Findings    []Finding         `json:"findings"`
	Events      []Event           `json:"events"`
	Phase       string            `json:"phase"`
	Progress    float64           `json:"progress"`
	Credentials *CredentialConfig `json:"credentials,omitempty"`
}

func (s *ScanSession) AddEvent(ev Event) {
	s.mu.Lock()
	s.Events = append(s.Events, ev)
	s.mu.Unlock()
}

func (s *ScanSession) AddFinding(f Finding) {
	s.mu.Lock()
	s.Findings = append(s.Findings, f)
	s.mu.Unlock()
}

func (s *ScanSession) SetStatus(status string) {
	s.mu.Lock()
	s.Status = status
	s.mu.Unlock()
}

func (s *ScanSession) SetPhase(phase string) {
	s.mu.Lock()
	s.Phase = phase
	s.mu.Unlock()
}

type Finding struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Target      string            `json:"target"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Evidence    map[string]string `json:"evidence"`
	MitreTags   []string          `json:"mitre_tags"`
	CVSS        float64           `json:"cvss"`
	Confirmed   bool              `json:"confirmed"`
	Timestamp   time.Time         `json:"timestamp"`
}

type CredentialConfig struct {
	Username     string            `json:"username,omitempty"`
	Password     string            `json:"password,omitempty"`
	Token        string            `json:"token,omitempty"`
	Cookie       string            `json:"cookie,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	AuthFlow     string            `json:"authFlow,omitempty"`
	LoginURL     string            `json:"loginUrl,omitempty"`
	SessionID    string            `json:"sessionId,omitempty"`
	SessionStore map[string]string `json:"sessionStore,omitempty"`
}

type Event struct {
	Timestamp string `json:"timestamp"`
	ScanID    string `json:"scan_id"`
	Type      string `json:"type"`
	Message   string `json:"message"`
}

type ScanStore struct {
	mu            sync.RWMutex
	scans         map[string]map[string]*ScanSession
	defaultTenant string
	stopCh        chan struct{}
}

func NewScanStore() *ScanStore {
	s := &ScanStore{
		scans:         make(map[string]map[string]*ScanSession),
		defaultTenant: "default",
		stopCh:        make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

func (s *ScanStore) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.PruneCompleted(1000)
		}
	}
}

func (s *ScanStore) AddWithTenant(tenantID string, scan *ScanSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scans[tenantID] == nil {
		s.scans[tenantID] = make(map[string]*ScanSession)
	}
	s.scans[tenantID][scan.ID] = scan
}

func (s *ScanStore) Add(scan *ScanSession) {
	s.AddWithTenant(s.defaultTenant, scan)
}

func (s *ScanStore) GetWithTenant(tenantID, id string) *ScanSession {
	s.mu.RLock()
	scan := s.scans[tenantID][id]
	s.mu.RUnlock()
	return scan
}

func (s *ScanStore) ListWithTenant(tenantID string) []*ScanSession {
	s.mu.RLock()
	out := make([]*ScanSession, 0, len(s.scans[tenantID]))
	for _, scan := range s.scans[tenantID] {
		out = append(out, scan)
	}
	s.mu.RUnlock()
	return out
}

func (s *ScanStore) ListCompleted() []*ScanSession {
	s.mu.RLock()
	var completed []*ScanSession
	for _, tenant := range s.scans {
		for _, scan := range tenant {
			if scan.Status == "completed" || scan.Status == "stopped" || scan.Status == "error" {
				completed = append(completed, scan)
			}
		}
	}
	s.mu.RUnlock()
	return completed
}

func (s *ScanStore) Get(id string) *ScanSession {
	return s.GetWithTenant(s.defaultTenant, id)
}

func (s *ScanStore) List() []*ScanSession {
	return s.ListWithTenant(s.defaultTenant)
}

func (s *ScanStore) DeleteWithTenant(tenantID, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scans[tenantID] != nil {
		delete(s.scans[tenantID], id)
	}
}

func (s *ScanStore) Delete(id string) {
	s.DeleteWithTenant(s.defaultTenant, id)
}

func (s *ScanStore) PruneCompleted(maxCompleted int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var completed []*ScanSession
	for _, tenant := range s.scans {
		for _, scan := range tenant {
			if scan.Status == "completed" || scan.Status == "stopped" || scan.Status == "error" {
				completed = append(completed, scan)
			}
		}
	}

	if len(completed) <= maxCompleted {
		return
	}

	for i := 0; i < len(completed)-maxCompleted; i++ {
		scan := completed[i]
		for _, tenant := range s.scans {
			if _, ok := tenant[scan.ID]; ok {
				delete(tenant, scan.ID)
				break
			}
		}
	}
}

func (s *ScanStore) UpdateProgressWithTenant(tenantID, id string, phase string, progress float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scans[tenantID] != nil {
		if scan, ok := s.scans[tenantID][id]; ok {
			scan.Phase = phase
			scan.Progress = progress
		}
	}
}

func (s *ScanStore) UpdateProgress(id string, phase string, progress float64) {
	s.UpdateProgressWithTenant(s.defaultTenant, id, phase, progress)
}

func (s *ScanStore) LoadFromDisk(diskStore *store.Store) {
	if diskStore == nil {
		return
	}
	scans := diskStore.ListScans("")
	for _, ps := range scans {
		tenantID := ps.TenantID
		if tenantID == "" {
			tenantID = s.defaultTenant
		}
		// Mark scans that were running on shutdown as stopped — no goroutine is running
		status := ps.Status
		if status == "running" || status == "queued" || status == "paused" {
			status = "stopped"
		}
		scan := &ScanSession{
			ID:        ps.ID,
			Target:    ps.Target,
			StartTime: ps.StartTime,
			Status:    status,
			Phase:     ps.Phase,
			Progress:  ps.Progress,
			Findings:  make([]Finding, 0),
			Events:    make([]Event, 0),
		}
		for _, pf := range ps.Findings {
			scan.Findings = append(scan.Findings, Finding{
				ID:          pf.ID,
				Type:        pf.Type,
				Severity:    pf.Severity,
				Target:      pf.Target,
				Title:       pf.Title,
				Description: pf.Description,
				Evidence:    pf.Evidence,
				MitreTags:   pf.MitreTags,
				CVSS:        pf.CVSS,
				Confirmed:   pf.Confirmed,
				Timestamp:   pf.Timestamp,
			})
		}
		s.AddWithTenant(tenantID, scan)
	}
}

func (s *ScanStore) AddFindingWithTenant(tenantID, scanID string, finding *Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scans[tenantID] != nil {
		if scan, ok := s.scans[tenantID][scanID]; ok {
			for _, existing := range scan.Findings {
				if existing.ID == finding.ID {
					return
				}
			}
			scan.Findings = append(scan.Findings, *finding)
		}
	}
}

func (s *ScanStore) AddFinding(scanID string, finding *Finding) {
	s.AddFindingWithTenant(s.defaultTenant, scanID, finding)
}

func (s *ScanStore) AddEventWithTenant(tenantID, scanID string, ev Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scans[tenantID] != nil {
		if scan, ok := s.scans[tenantID][scanID]; ok {
			scan.Events = append(scan.Events, ev)
		}
	}
}

func (s *ScanStore) AddEvent(scanID string, ev Event) {
	s.AddEventWithTenant(s.defaultTenant, scanID, ev)
}

func (s *ScanStore) AllFindings() []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var all []Finding
	for _, tenant := range s.scans {
		for _, scan := range tenant {
			scan.mu.RLock()
			all = append(all, scan.Findings...)
			scan.mu.RUnlock()
		}
	}
	return all
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

type RunScanFunc func(scanID, target string, phases []string) string
type StopScanFunc func(scanID string)

type Server struct {
	*webserver.Server
	staticDir             string
	mux                   *http.ServeMux
	port                  int
	startTime             time.Time
	scanStore             *ScanStore
	diskStore             *store.Store
	wsHub                 *websocket.Hub
	cfg                   ServerConfig
	httpSrv               *http.Server
	runScanFn             RunScanFunc
	runScanMu             sync.RWMutex
	stopScanFn            StopScanFunc
	embeddedFS            embed.FS
	useEmbedded           bool
	scanControls          *worker.ScanControls
	rateLimiter           *ratelimit.RateLimiter
	autonomousHandler     *AutonomousHandler
	reportHandler         *ReportHandler
	envStore              *config.EnvStore
	persistStore          *store.PersistentStore
	attackGraph           *graph.AttackGraph
	pathSimulator         *attackpath.PathSimulator
	remediationGen        *coderemediation.FixGenerator
	appConfig             *config.EnterpriseConfig
	auditLogger           *audit.StructuredLogger
	appMetrics            *metrics.Metrics
	secretsLoader         *secrets.Loader
	apiKeyManager         *apikey.Manager
	loginHandler          *auth.LoginHandler
	usageTracker          *UsageTracker
	notificationEngine    *NotificationEngine
	agentManager          *agentdeploy.AgentManager
	exposureMonitor       *exposure.ExposureMonitor
	approvalEngine        *approvals.WorkflowEngine
	airgapManager         *airgap.AirGapManager
	riskEngine            *risk.RiskEngine
	samlService           *saml.SAMLService
	evidenceSigner        *evidence.EvidenceSigner
	knowledgeGraph        *knowledgegraph.KnowledgeGraph
	validationLoop        *validationloop.ValidationLoop
	verifierEngine        *verifier.Engine
	purpleTeam            *purpleteam.PurpleTeamEngine
	copilotEngine         *copilot.CopilotEngine
	asmEngine             *asm.ASMEngine
	complianceBuilder     *compliancebuilder.ComplianceBuilder
	collaborationEngine   *collaboration.CollaborationEngine
	pythonDaemon          *pythondaemon.Daemon
	ransomwareEngine      *ransomware.Engine
	packetInjectionEngine *packetinjection.Engine
	netsimEngine          *netsim.Engine
}

func New(cfg ServerConfig, sched *scheduler.Scheduler, bountyMgr *bounty.Manager) *Server {
	mux := http.NewServeMux()
	staticDir := cfg.StaticDir
	if staticDir == "" {
		staticDir = "./static"
	}
	storeDir := cfg.StoreDir
	if storeDir == "" {
		storeDir = "./data"
	}

	useEmbedded := false
	if _, err := os.Stat(staticDir); err != nil {
		useEmbedded = true
	}

	s := &Server{
		Server:    webserver.New(cfg.Port, cfg.SessionSecret),
		mux:       mux,
		port:      cfg.Port,
		startTime: time.Now(),
		scanStore: NewScanStore(),
		diskStore: store.New(storeDir),
		wsHub:     websocket.NewHubWithAuth(func(r *http.Request) bool { return true }, []byte(cfg.SessionSecret)),

		cfg:                   cfg,
		staticDir:             staticDir,
		embeddedFS:            frontend.Dist,
		useEmbedded:           useEmbedded,
		envStore:              config.NewEnvStore(filepath.Join(storeDir, "env_overrides.json")),
		persistStore:          store.NewPersistentStore(storeDir),
		appConfig:             config.LoadEnterprise(),
		auditLogger:           audit.GetStructured(),
		appMetrics:            metrics.Get(),
		secretsLoader:         secrets.New(),
		apiKeyManager:         apikey.NewManager(filepath.Join(storeDir, "apikeys.json")),
	}
	s.scanStore.LoadFromDisk(s.diskStore)

	_ = os.Getenv("ARES_OIDC_ISSUER") // OIDC is disabled; always running in no-auth mode

	s.appConfig = config.LoadEnterprise()
	s.auditLogger = audit.GetStructured()
	s.appMetrics = metrics.Get()
	s.secretsLoader = secrets.New()
	s.apiKeyManager = apikey.NewManager(filepath.Join(storeDir, "apikeys.json"))

	rlRate := 60
	rlBurst := 100
	if s.appConfig != nil {
		rlRate = s.appConfig.HTTP.RateLimit
		rlBurst = s.appConfig.HTTP.RateLimitBurst
	}
	s.rateLimiter = ratelimit.NewRateLimiter(rlRate, rlBurst)
	s.usageTracker = NewUsageTracker()
	s.notificationEngine = NewNotificationEngine()

	return s
}

func (s *Server) SetLoginHandler(lh *auth.LoginHandler) {
	s.loginHandler = lh
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	authRequired := os.Getenv("ARES_AUTH_REQUIRED") == "true"
	return func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			w.Header().Set("Content-Type", "application/json")
		}

		var role auth.UserRole = auth.RoleViewer
		var user string = ""

		// 1. Check X-API-Key header
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" && s.apiKeyManager != nil {
			if k, err := s.apiKeyManager.Validate(apiKey); err == nil {
				role = k.Role
				user = k.Name
				s.apiKeyManager.RecordUsage(k.ID)
			} else {
				http.Error(w, "invalid api key", http.StatusUnauthorized)
				return
			}
		}

		// 2. Check Authorization: Bearer <token> for session-based auth
		if apiKey == "" && s.loginHandler != nil {
			token := auth.ExtractToken(r)
			if token != "" {
				if session, err := s.loginHandler.ValidateToken(token); err == nil {
					role = session.Role
					user = session.Username
				} else {
					http.Error(w, "unauthorized: invalid or expired session", http.StatusUnauthorized)
					return
				}
			}
		}

		// 3. If auth is required and no credentials were provided, reject
		if authRequired && user == "" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), sessionRoleKey, role)
		ctx = context.WithValue(ctx, sessionUserKey, user)
		next(w, r.WithContext(ctx))
	}
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func (s *Server) adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		role, _ := r.Context().Value(sessionRoleKey).(auth.UserRole)
		if role != auth.RoleAdmin {
			http.Error(w, "forbidden: admin role required", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

type contextKey string

const sessionRoleKey contextKey = "session_role"
const sessionUserKey contextKey = "session_user"

func (s *Server) csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return next
}

func isAllowedOrigin(origin string, allowed []string) bool {
	if len(allowed) == 0 {
		if envOrigins := os.Getenv("ARES_CORS_ALLOWED_ORIGINS"); envOrigins != "" {
			for _, a := range strings.Split(envOrigins, ",") {
				if origin == strings.TrimSpace(a) {
					return true
				}
			}
			return false
		}
		return origin == "http://localhost:8080" || origin == "https://localhost:8080"
	}
	for _, a := range allowed {
		if origin == a {
			return true
		}
	}
	return false
}

func (s *Server) getTenantID(r *http.Request) string {
	return "default"
}

func (s *Server) setupRoutes() {
	// Wrapped middleware that applies CSRF to mutation methods (POST, PUT, DELETE, PATCH)
	secureMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return s.csrfMiddleware(next)
	}

	s.mux.HandleFunc("/favicon.ico", s.handleFavicon)
	s.mux.HandleFunc("/favicon.svg", s.handleFavicon)
	s.mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
	s.mux.HandleFunc("/", s.handleIndex)
	if s.useEmbedded {
		distFS, err := fs.Sub(s.embeddedFS, "dist")
		if err == nil {
			s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(distFS))))
			s.mux.Handle("/assets/", mimeAwareFileServer(http.FS(distFS)))
		}
	} else {
		staticDir := filepath.Join(s.staticDir, "static")
		if _, err := os.Stat(staticDir); err == nil {
			s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
		}
		assetsDir := filepath.Join(s.staticDir, "assets")
		if _, err := os.Stat(assetsDir); err == nil {
			s.mux.Handle("/assets/", mimeAwareFileServer(http.Dir(s.staticDir)))
		}
	}
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/livez", s.handleHealth)
	s.mux.HandleFunc("/readyz", s.handleReadiness)

	s.mux.HandleFunc("/ws", s.authMiddleware(s.handleLiveWebSocket))
	s.mux.HandleFunc("/ws/", s.authMiddleware(s.handleLiveWebSocket))

	s.mux.Handle("/api/scans", s.authMiddleware(secureMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleListScans(w, r)
		case http.MethodPost:
			s.handleStartScan(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	s.mux.Handle("/api/scans/compare", s.authMiddleware(secureMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleScanCompare(w, r)
	})))

	s.mux.Handle("/api/scans/history", s.authMiddleware(secureMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.handleScanHistory(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	s.mux.Handle("/api/scans/", s.authMiddleware(secureMiddleware(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/scans/")
		parts := strings.SplitN(path, "/", 2)
		switch {
		case r.Method == http.MethodGet && path == "":
			s.handleListScans(w, r)
		case len(parts) == 1 && parts[0] != "":
			s.handleScanDetail(w, r, parts[0])
		case len(parts) == 2:
			id, action := parts[0], parts[1]
			switch action {
			case "stop":
				s.handleStopScan(w, r, id)
			case "events":
				s.handleSSE(w, r, id)
			case "findings":
				s.handleFindings(w, r, id)
			case "report":
				s.handleReport(w, r, id)
			case "report-json":
				s.handleReportJSON(w, r, id)
			case "report-pdf":
				s.handleReportPDF(w, r, id)
			case "report-text":
				s.handleReportText(w, r, id)
			case "note":
				s.handleNote(w, r, id)
			case "retest":
				s.handleRetest(w, r, id)
			case "live-status":
				s.handleLiveScanStatus(w, r, id)
			case "activity":
				s.handleScanActivity(w, r, id)
			default:
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	})))



	s.mux.HandleFunc("/api/auth/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"authenticated","username":"admin","role":"admin"}`))
	})

	s.mux.Handle("/api/graph/export", s.authMiddleware(s.handleGraphExport))
	s.mux.Handle("/api/graph/dot", s.authMiddleware(s.handleGraphDOT))
	s.mux.Handle("/api/graph/mermaid", s.authMiddleware(s.handleGraphMermaid))
	s.mux.Handle("/api/graph/chains", s.authMiddleware(s.handleGraphChains))

	s.mux.Handle("/api/attack-paths", s.authMiddleware(s.handleAttackPaths))
	s.mux.Handle("/api/attack-paths/report", s.authMiddleware(s.handleAttackPathReport))
	s.mux.Handle("/api/attack-paths/blast-radius", s.authMiddleware(s.handleBlastRadius))

	s.mux.Handle("/api/triggers/webhook", s.authMiddleware(s.handleTriggerWebhook))
	s.mux.HandleFunc("/api/triggers/", s.authMiddleware(s.handleTriggerManagement))





	// Admin-protected routes using adminMiddleware
	s.mux.Handle("/api/admin/settings", s.adminMiddleware(secureMiddleware(s.handleSettingsGet)))




	cloudMux := http.NewServeMux()
	cloudscanner.RegisterCloudScannerHandlers(cloudMux)
	s.mux.Handle("/api/cloud/", s.authMiddleware(cloudMux.ServeHTTP))

	redMux := http.NewServeMux()
	redteam.RegisterRedTeamHandlers(redMux)
	s.mux.Handle("/api/redteam/", s.authMiddleware(redMux.ServeHTTP))

	// Dashboard API endpoints
	s.mux.Handle("/api/metrics", s.authMiddleware(s.handleMetrics))
	s.mux.Handle("/api/scans/active", s.authMiddleware(s.handleActiveScans))
	s.mux.Handle("/api/stats/severity", s.authMiddleware(s.handleSeverityBreakdown))
	s.mux.Handle("/api/stats/vuln-categories", s.authMiddleware(s.handleVulnCategories))
	s.mux.Handle("/api/stats/scan-queue", s.authMiddleware(s.handleScanQueue))
	s.mux.Handle("/api/findings/critical/recent", s.authMiddleware(s.handleRecentCriticals))

	s.mux.Handle("/api/findings", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.handleFindingsList(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	s.mux.Handle("/api/findings/", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/findings/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) == 1 && parts[0] != "" {
			s.handleFindingDetail(w, r, parts[0])
		} else if len(parts) == 2 && parts[1] == "status" {
			s.handleFindingStatus(w, r)
		} else if len(parts) == 2 && parts[1] == "validate" {
			if r.Method == http.MethodPost {
				s.handleFindingValidate(w, r, parts[0])
			} else {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		} else {
			http.NotFound(w, r)
		}
	}))

	s.mux.Handle("/api/projects", s.authMiddleware(s.handleProjects))
	s.mux.Handle("/api/scope", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleScopeList(w, r)
		case http.MethodPost:
			s.handleScopeAdd(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	s.mux.Handle("/api/scope/", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/scope/")
		if strings.HasSuffix(path, "/delete") {
			id := strings.TrimSuffix(path, "/delete")
			s.handleScopeDelete(w, r, id)
		} else {
			http.NotFound(w, r)
		}
	}))

	s.mux.Handle("/api/settings", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleSettingsGet(w, r)
		case http.MethodPut:
			s.handleSettingsUpdate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	s.mux.Handle("/api/settings/webhook", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleWebhookSettingsGet(w, r)
		case http.MethodPut:
			s.handleWebhookSettingsUpdate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	s.mux.Handle("/api/settings/webhook/test", s.authMiddleware(s.handleWebhookTest))
	s.mux.Handle("/api/settings/webhook/siem-presets", s.authMiddleware(s.handleSIEMPresets))
	s.mux.Handle("/api/settings/rate-limit", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleRateLimitGet(w, r)
		case http.MethodPut:
			s.handleRateLimitUpdate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	s.mux.Handle("/api/settings/discord", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleDiscordGet(w, r)
		case http.MethodPut:
			s.handleDiscordUpdate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	s.mux.Handle("/api/settings/agentmail", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleAgentMailGet(w, r)
		case http.MethodPut:
			s.handleAgentMailUpdate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	s.mux.Handle("/api/settings/llm", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleLLMSettingsGet(w, r)
		case http.MethodPut:
			s.handleLLMSettingsUpdate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	s.mux.Handle("/api/settings/team", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleTeamList(w, r)
		case http.MethodPost:
			s.handleTeamInvite(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	s.mux.Handle("/api/settings/env", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleEnvGet(w, r)
		case http.MethodPut:
			s.handleEnvUpdate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	s.mux.Handle("/api/tenant/usage", s.authMiddleware(s.handleTenantUsage))
	s.mux.Handle("/api/notifications", s.authMiddleware(s.handleListNotifications))

	// Self-serve portal endpoints (no auth for registration)
	s.mux.HandleFunc("/api/portal/register", s.handlePortalRegister)
	s.mux.Handle("/api/portal/plans", s.authMiddleware(s.handlePortalPlan))
	s.mux.Handle("/api/portal/billing", s.authMiddleware(s.handlePortalBilling))

	s.mux.Handle("/api/keys", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleListAPIKeys(w, r)
		case http.MethodPost:
			s.handleCreateAPIKey(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	s.mux.Handle("/api/keys/", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/keys/")
		switch r.Method {
		case http.MethodDelete:
			s.handleDeleteAPIKey(w, r, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	s.mux.Handle("/api/upload-logo", s.authMiddleware(s.handleUploadLogo))
	s.mux.Handle("/api/upload-targets", s.authMiddleware(s.handleUploadTargets))

	s.mux.Handle("/api/queue/status", s.authMiddleware(s.handleQueueStatus))
	s.mux.Handle("/api/queue/resume", s.authMiddleware(s.handleQueueResume))
	s.mux.Handle("/api/queue/clear", s.authMiddleware(s.handleQueueClear))

	s.mux.HandleFunc("/api/status", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"current_phase": 0})
	}))

	s.mux.Handle("/api/instances/", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/instances/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) == 2 && r.Method == http.MethodPost {
			id, action := parts[0], parts[1]
			switch action {
			case "pause":
				s.handleInstancePause(w, r, id)
			case "resume":
				s.handleInstanceResume(w, r, id)
			case "restart":
				s.handleInstanceRestart(w, r, id)
			default:
				http.NotFound(w, r)
			}
		} else if len(parts) == 1 && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(s.scanStore.List())
		} else {
			http.NotFound(w, r)
		}
	}))

	s.mux.Handle("/api/compliance/reports", s.authMiddleware(s.handleComplianceReports))
	s.mux.Handle("/api/compliance/findings", s.authMiddleware(s.handleComplianceFindings))

	s.mux.Handle("/api/reports/export", s.authMiddleware(s.handleReportExport))
	s.mux.Handle("/api/scans/presets", s.authMiddleware(s.handleScanPresets))
	s.mux.Handle("/api/scans/submit", s.authMiddleware(s.handleScanSubmit))

	s.mux.Handle("/api/remediation/generate", s.authMiddleware(s.handleRemediationGenerate))

	if s.autonomousHandler != nil {
		s.mux.Handle("/api/autonomous", s.authMiddleware(s.autonomousHandler.ServeHTTP))
		s.mux.Handle("/api/autonomous/", s.authMiddleware(s.autonomousHandler.ServeHTTP))
	}
	if s.reportHandler != nil {
		s.mux.Handle("/api/reports/generate", s.authMiddleware(s.reportHandler.ServeHTTP))
		s.mux.Handle("/api/reports/manage", s.authMiddleware(s.reportHandler.ServeHTTP))
	}

	agentMux := http.NewServeMux()
	agentdeploy.RegisterAgentHandlers(agentMux, s.agentManager)
	s.mux.Handle("/api/agents", s.authMiddleware(agentMux.ServeHTTP))
	s.mux.Handle("/api/agents/", s.authMiddleware(agentMux.ServeHTTP))

	exposureMux := http.NewServeMux()
	exposure.RegisterExposureHandlers(exposureMux, s.exposureMonitor)
	s.mux.Handle("/api/exposure", s.authMiddleware(exposureMux.ServeHTTP))
	s.mux.Handle("/api/exposure/", s.authMiddleware(exposureMux.ServeHTTP))

	approvalMux := http.NewServeMux()
	approvals.RegisterApprovalHandlers(approvalMux, s.approvalEngine)
	s.mux.Handle("/api/approvals", s.authMiddleware(approvalMux.ServeHTTP))
	s.mux.Handle("/api/approvals/", s.authMiddleware(approvalMux.ServeHTTP))
	s.mux.Handle("/api/emergency-stop", s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		approvalMux.ServeHTTP(w, r)
	}))

	riskMux := http.NewServeMux()
	risk.RegisterRiskHandlers(riskMux, s.riskEngine)
	s.mux.Handle("/api/risk", s.authMiddleware(riskMux.ServeHTTP))
	s.mux.Handle("/api/risk/", s.authMiddleware(riskMux.ServeHTTP))

	samlMux := http.NewServeMux()
	saml.RegisterSAMLHandlers(samlMux, s.samlService)
	s.mux.Handle("/api/saml/", s.authMiddleware(samlMux.ServeHTTP))
	s.mux.Handle("/api/scim/", s.authMiddleware(samlMux.ServeHTTP))

	evidenceMux := http.NewServeMux()
	evidence.RegisterEvidenceHandlers(evidenceMux, s.evidenceSigner)
	s.mux.Handle("/api/evidence", s.authMiddleware(evidenceMux.ServeHTTP))
	s.mux.Handle("/api/evidence/", s.authMiddleware(evidenceMux.ServeHTTP))

	kgMux := http.NewServeMux()
	knowledgegraph.RegisterGraphHandlers(kgMux, s.knowledgeGraph)
	s.mux.Handle("/api/knowledge-graph", s.authMiddleware(kgMux.ServeHTTP))
	s.mux.Handle("/api/knowledge-graph/", s.authMiddleware(kgMux.ServeHTTP))

	valMux := http.NewServeMux()
	validationloop.RegisterValidationHandlers(valMux, s.validationLoop)
	s.mux.Handle("/api/validation-loops", s.authMiddleware(valMux.ServeHTTP))
	s.mux.Handle("/api/validation-loops/", s.authMiddleware(valMux.ServeHTTP))

	ptMux := http.NewServeMux()
	purpleteam.RegisterPurpleTeamHandlers(ptMux, s.purpleTeam)
	s.mux.Handle("/api/purple-team", s.authMiddleware(ptMux.ServeHTTP))
	s.mux.Handle("/api/purple-team/", s.authMiddleware(ptMux.ServeHTTP))

	copilot.RegisterCopilotHandlers(s.mux, s.copilotEngine)

	asmMux := http.NewServeMux()
	asm.RegisterASMHandlers(asmMux, s.asmEngine)
	s.mux.Handle("/api/asm", s.authMiddleware(asmMux.ServeHTTP))
	s.mux.Handle("/api/asm/", s.authMiddleware(asmMux.ServeHTTP))

	cbMux := http.NewServeMux()
	compliancebuilder.RegisterComplianceBuilderHandlers(cbMux, s.complianceBuilder)
	s.mux.Handle("/api/compliance-frameworks", s.authMiddleware(cbMux.ServeHTTP))
	s.mux.Handle("/api/compliance-frameworks/", s.authMiddleware(cbMux.ServeHTTP))

	collabMux := http.NewServeMux()
	collaboration.RegisterCollaborationHandlers(collabMux, s.collaborationEngine)
	s.mux.Handle("/api/collaboration", s.authMiddleware(collabMux.ServeHTTP))
	s.mux.Handle("/api/collaboration/", s.authMiddleware(collabMux.ServeHTTP))



	ransomwareMux := http.NewServeMux()
	ransomware.RegisterHandlers(ransomwareMux, s.ransomwareEngine)
	s.mux.Handle("/api/ransomware", s.authMiddleware(ransomwareMux.ServeHTTP))
	s.mux.Handle("/api/ransomware/", s.authMiddleware(ransomwareMux.ServeHTTP))

	piMux := http.NewServeMux()
	packetinjection.RegisterHandlers(piMux, s.packetInjectionEngine)
	s.mux.Handle("/api/packet/", s.authMiddleware(piMux.ServeHTTP))



	netsimMux := http.NewServeMux()
	netsim.RegisterHandlers(netsimMux, s.netsimEngine)
	s.mux.Handle("/api/netsim/", s.authMiddleware(netsimMux.ServeHTTP))
}

// SetReportHandler wires the report generation handler into the web server
func (s *Server) SetReportHandler(rh *ReportHandler) {
	s.reportHandler = rh
}

// ScanStore returns the server's scan store for external use
func (s *Server) ScanStore() *ScanStore {
	return s.scanStore
}

func (s *Server) Start() error {
	s.setupRoutes()
	addr := fmt.Sprintf(":%d", s.port)

	s.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           s.rateLimiter.Middleware(s.recoveryMiddleware(securityHeadersMiddleware(corsMiddleware(s.mux)))),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
	}

	if s.pythonDaemon != nil && !s.pythonDaemon.IsRunning() {
		logger.Error("[Web] Python daemon not running at startup — malware features degraded", nil)
	}

	tlsCert := os.Getenv("ARES_TLS_CERT")
	tlsKey := os.Getenv("ARES_TLS_KEY")
	if tlsCert != "" && tlsKey != "" {
		logger.Info(fmt.Sprintf("[Web] Starting on https://localhost%s", addr))
		go func() {
			if err := s.httpSrv.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
				logger.Error(fmt.Sprintf("[Web] Server error: %v", err))
			}
		}()
	} else {
		logger.Info(fmt.Sprintf("[Web] Starting on http://localhost%s (TLS not configured)", addr))
		go func() {
			if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error(fmt.Sprintf("[Web] Server error: %v", err))
			}
		}()
	}
	return nil
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; connect-src 'self'; font-src 'self' https://fonts.gstatic.com;")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func mimeAwareFileServer(fsys http.FileSystem) http.Handler {
	fsrv := http.FileServer(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		} else if strings.HasSuffix(path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else if strings.HasSuffix(path, ".svg") {
			w.Header().Set("Content-Type", "image/svg+xml")
		} else if strings.HasSuffix(path, ".woff2") {
			w.Header().Set("Content-Type", "font/woff2")
		} else if strings.HasSuffix(path, ".woff") {
			w.Header().Set("Content-Type", "font/woff")
		} else if strings.HasSuffix(path, ".png") {
			w.Header().Set("Content-Type", "image/png")
		} else if strings.HasSuffix(path, ".webp") {
			w.Header().Set("Content-Type", "image/webp")
		} else if strings.HasSuffix(path, ".json") {
			w.Header().Set("Content-Type", "application/json")
		}
		fsrv.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	allowedOrigins := os.Getenv("ARES_CORS_ALLOWED_ORIGINS")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			allow := false
			if allowedOrigins == "*" {
				allow = true
			} else {
				for _, a := range strings.Split(allowedOrigins, ",") {
					if origin == strings.TrimSpace(a) {
						allow = true
						break
					}
				}
				if !allow {
					if strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "https://localhost") {
						allow = true
					}
				}
			}
			if allow {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-CSRF-Token")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("[Web] HTTP handler panic recovered", logger.Fields{
					"panic":  fmt.Sprintf("%v", rec),
					"path":   r.URL.Path,
					"method": r.Method,
				})
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)
		if lrw.statusCode >= 400 {
			audit.LogStructured("system", "http_error", r.URL.Path, "", fmt.Sprintf("%d", lrw.statusCode),
				audit.WithRemoteAddr(r.RemoteAddr),
				audit.WithUserAgent(r.UserAgent()),
			)
		}
	})
}

func (s *Server) Stop(timeout time.Duration) error {
	if s.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := s.httpSrv.Shutdown(ctx); err != nil {
			logger.Error("[Web] HTTP shutdown error", logger.Fields{"error": err})
		}
	}
	if s.agentManager != nil {
		s.agentManager.Stop()
	}
	if s.exposureMonitor != nil {
		s.exposureMonitor.Stop()
	}
	if s.validationLoop != nil {
		s.validationLoop.Stop()
	}
	if s.pythonDaemon != nil {
		logger.Info("[Web] Stopping Python daemon (last in shutdown order)", nil)
		s.pythonDaemon.Stop()
	}
	logger.Info("[Web] Server shutdown complete", nil)
	return nil
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	if s.useEmbedded {
		data, err := s.embeddedFS.ReadFile("favicon.svg")
		if err != nil {
			http.Error(w, "favicon not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(data)
		return
	}
	// Try .svg first, then .png
	for _, name := range []string{"favicon.svg", "favicon.png"} {
		path := filepath.Join(s.staticDir, name)
		if _, err := os.Stat(path); err == nil {
			ct := "image/png"
			if name == "favicon.svg" {
				ct = "image/svg+xml"
			}
			w.Header().Set("Content-Type", ct)
			http.ServeFile(w, r, path)
			return
		}
	}
	http.Error(w, "favicon not found", http.StatusNotFound)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Serve index.html for all SPA routes (not just "/").
	// This lets React Router handle /login, /dashboard, etc.
	// But reject unknown API paths so they 404 instead of getting HTML.
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if s.useEmbedded {
		data, err := s.embeddedFS.ReadFile("dist/index.html")
		if err != nil {
			http.Error(w, "embedded frontend not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.staticDir, "index.html"))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	checks := map[string]string{}
	if s.persistStore == nil {
		status = "degraded"
		checks["store"] = "not initialized"
	}
	if s.wsHub == nil {
		status = "degraded"
		checks["websocket"] = "not initialized"
	}
	if s.scanControls == nil {
		status = "degraded"
		checks["scan_controls"] = "not initialized"
	}
	if s.pythonDaemon != nil && !s.pythonDaemon.IsRunning() {
		status = "degraded"
		checks["python_daemon"] = "not running"
	} else if s.pythonDaemon != nil {
		cs := s.pythonDaemon.GetCircuitState()
		if cs == 2 {
			status = "degraded"
			checks["python_daemon"] = "circuit breaker open"
		} else {
			checks["python_daemon"] = "ok"
		}
	}
	if s.appMetrics != nil {
		checks["metrics"] = fmt.Sprintf("requests=%d errors=%d",
			s.appMetrics.RequestCount.Load(),
			s.appMetrics.RequestErrors.Load())
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"uptime":  time.Since(s.startTime).String(),
		"version": "1.0.0",
		"checks":  checks,
	})
}

func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	checks := map[string]bool{}
	allReady := true

	if s.persistStore == nil {
		checks["store"] = false
		allReady = false
	} else {
		checks["store"] = true
	}

	if s.wsHub == nil {
		checks["websocket"] = false
		allReady = false
	} else {
		checks["websocket"] = true
	}

	if s.pythonDaemon != nil {
		err := s.pythonDaemon.HealthCheck()
		checks["python_daemon"] = err == nil
		if err != nil {
			logger.Warn("[Web] readiness daemon check failed", logger.Fields{"error": err})
		}
	} else {
		checks["python_daemon"] = true
	}

	if s.appMetrics != nil {
		checks["metrics"] = true
	}

	status := "ok"
	if !allReady {
		status = "not ready"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"checks": checks,
	})
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	w.Header().Set("Content-Type", "application/json")
	scans := s.scanStore.ListWithTenant(tenantID)

	type scanListItem struct {
		ID            string  `json:"id"`
		Target        string  `json:"target"`
		StartTime     string  `json:"start_time"`
		Status        string  `json:"status"`
		Phase         string  `json:"phase"`
		Progress      float64 `json:"progress"`
		FindingsCount int     `json:"findings_count"`
		ETASeconds    int     `json:"eta_seconds"`
	}

	offset := 0
	limit := len(scans)
	if o := r.URL.Query().Get("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if offset < 0 {
		offset = 0
	}
	if limit < 0 {
		limit = 0
	}

	total := len(scans)
	if offset >= total {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":  []scanListItem{},
			"total": total,
			"limit": limit,
			"offset": offset,
		})
		return
	}
	end := offset + limit
	if end > total {
		end = total
	}

	items := make([]scanListItem, 0, end-offset)
	for _, scan := range scans[offset:end] {
		etaSeconds := 0
		if scan.Progress > 0 && scan.Status == "running" {
			elapsed := time.Since(scan.StartTime).Seconds()
			rate := scan.Progress / elapsed
			remaining := (1.0 - scan.Progress) / rate
			etaSeconds = int(remaining)
			if etaSeconds < 0 {
				etaSeconds = 0
			}
		}
		items = append(items, scanListItem{
			ID:            scan.ID,
			Target:        scan.Target,
			StartTime:     scan.StartTime.Format(time.RFC3339),
			Status:        scan.Status,
			Phase:         scan.Phase,
			Progress:      scan.Progress,
			FindingsCount: len(scan.Findings),
			ETASeconds:    etaSeconds,
		})
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":   items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target        string            `json:"target"`
		Phases        []string          `json:"phases"`
		AuthorizedBy  string            `json:"authorized_by"`
		Authorization string            `json:"authorization"`
		Credentials   *CredentialConfig `json:"credentials,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if !requireJSONContentType(w, r) {
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := security.ValidateTarget(req.Target); err != nil {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	tenantID := s.getTenantID(r)

	// Enforce scan quota
	if err := s.checkScanQuota(tenantID); err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	scanID := uuid.New()
	scan := &ScanSession{
		ID:          scanID,
		Target:      req.Target,
		StartTime:   time.Now(),
		Status:      "running",
		Phase:       "initializing",
		Progress:    0,
		Findings:    make([]Finding, 0),
		Events:      make([]Event, 0),
		Credentials: req.Credentials,
	}
	s.scanStore.AddWithTenant(tenantID, scan)
	s.Server.Push(scanID, "SCAN_START", fmt.Sprintf("Scan started for target: %s", req.Target))
	s.usageTracker.RecordScanStart(tenantID, scanID)

	if fn := s.getRunScanFn(); fn != nil {
		phases := req.Phases
		if len(phases) == 0 {
			phases = []string{"recon", "scan", "exploit", "report"}
		}
		go func() {
			fn(scanID, req.Target, phases)
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":             scanID,
		"target":         req.Target,
		"status":         "running",
		"authorized_by":  req.AuthorizedBy,
		"authorized":     req.Authorization != "",
		"authenticated":  req.Credentials != nil,
	})
}

func (s *Server) ScanCredentials(scanID string) *CredentialConfig {
	session := s.scanStore.Get(scanID)
	if session == nil {
		return nil
	}
	return session.Credentials
}

func (s *Server) SetRunScanFunc(fn RunScanFunc) {
	s.runScanMu.Lock()
	s.runScanFn = fn
	s.runScanMu.Unlock()
}

func (s *Server) getRunScanFn() RunScanFunc {
	s.runScanMu.RLock()
	defer s.runScanMu.RUnlock()
	return s.runScanFn
}

func (s *Server) SetStopScanFunc(fn StopScanFunc) {
	s.stopScanFn = fn
}

func (s *Server) SetScanControls(sc *worker.ScanControls) {
	s.scanControls = sc
}

func (s *Server) UpdateScanProgress(scanID, status, phase string, progress float64) {
	if status != "" {
		scan := s.scanStore.Get(scanID)
		if scan != nil {
			tenantID := s.scanStore.resolveTenant(scanID)
			scan.SetStatus(status)
			if status == "completed" || status == "stopped" || status == "failed" || status == "error" {
				s.notifyScanComplete(scanID, tenantID, scan.Target, status)
			}
		}
	}
	// Terminal states always force correct progress
	if status == "completed" {
		progress = 1.0
	} else if status == "failed" || status == "error" || status == "stopped" {
		progress = 0
	} else if progress > 1.0 {
		progress = progress / 100.0
	}
	if phase != "" {
		s.scanStore.UpdateProgress(scanID, phase, progress)
	} else if status == "failed" || status == "error" || status == "stopped" {
		s.scanStore.UpdateProgress(scanID, status, progress)
	} else if status == "completed" {
		s.scanStore.UpdateProgress(scanID, "completed", 1.0)
	}
	// Persist to disk AFTER progress normalization so the saved value is correct
	if status != "" && s.diskStore != nil && (status == "completed" || status == "stopped" || status == "failed" || status == "error") {
		scan := s.scanStore.Get(scanID)
		if scan != nil {
			tid := s.scanStore.resolveTenant(scanID)
			scan.mu.RLock()
			ps := &store.PersistedScan{
				ID:        scan.ID,
				Target:    scan.Target,
				StartTime: scan.StartTime,
				Status:    scan.Status,
				Phase:     scan.Phase,
				Progress:  scan.Progress,
			}
			for _, f := range scan.Findings {
				ps.Findings = append(ps.Findings, store.PersistedFinding{
					ID:          f.ID,
					ScanID:      scan.ID,
					Type:        f.Type,
					Severity:    f.Severity,
					Target:      f.Target,
					Title:       f.Title,
					Description: f.Description,
					Evidence:    f.Evidence,
					MitreTags:   f.MitreTags,
					CVSS:        f.CVSS,
					Confirmed:   f.Confirmed,
					Timestamp:   f.Timestamp,
				})
				s.usageTracker.RecordFinding(tid, f.Severity)
				if strings.EqualFold(f.Severity, "critical") {
					s.notifyCriticalFinding(scanID, tid, f.Title)
				}
			}
			scan.mu.RUnlock()
			s.diskStore.SaveScan(ps)
		}
	}
}

func (ss *ScanStore) resolveTenant(scanID string) string {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	for tenantID, scans := range ss.scans {
		if _, ok := scans[scanID]; ok {
			return tenantID
		}
	}
	return "default"
}

func (s *Server) handleLiveScanStatus(w http.ResponseWriter, r *http.Request, id string) {
	tenantID := s.getTenantID(r)
	scan := s.scanStore.GetWithTenant(tenantID, id)
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	scan.mu.RLock()
	findingsCount := len(scan.Findings)
	events := scan.Events
	status := scan.Status
	phase := scan.Phase
	progress := scan.Progress
	startTime := scan.StartTime
	scan.mu.RUnlock()

	elapsed := time.Since(startTime).Seconds()
	etaSeconds := 0
	if progress > 0 && status == "running" {
		rate := progress / elapsed
		remaining := (1.0 - progress) / rate
		etaSeconds = int(remaining)
	}

	liveEvents := events
	if len(liveEvents) > 10 {
		liveEvents = liveEvents[len(liveEvents)-10:]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id":       id,
		"status":        status,
		"phase":         phase,
		"progress":      progress,
		"findings":      findingsCount,
		"elapsed_sec":   int(elapsed),
		"eta_sec":       etaSeconds,
		"started_at":    startTime.Format(time.RFC3339),
		"last_actions":  liveEvents,
	})
}

func (s *Server) handleScanDetail(w http.ResponseWriter, r *http.Request, path string) {
	tenantID := s.getTenantID(r)
	if tenantID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := path
	scan := s.scanStore.GetWithTenant(tenantID, id)
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	scan.mu.RLock()
	findings := make([]FindingJSON, 0, len(scan.Findings))
	for _, f := range scan.Findings {
		status := "open"
		ep := f.Target
		if e, ok := f.Evidence["endpoint"]; ok && e != "" {
			ep = e
		}
		findings = append(findings, FindingJSON{
			ID:           f.ID,
			Title:        f.Title,
			Severity:     f.Severity,
			Endpoint:     ep,
			Status:       status,
			DiscoveredAt: f.Timestamp.Format(time.RFC3339),
			CVSSScore:    f.CVSS,
			Confirmed:    f.Confirmed,
		})
	}
	progress := scan.Progress
	startTime := scan.StartTime
	etaSeconds := 0
	if progress > 0 && scan.Status == "running" {
		elapsed := time.Since(startTime).Seconds()
		rate := progress / elapsed
		remaining := (1.0 - progress) / rate
		etaSeconds = int(remaining)
		if etaSeconds < 0 {
			etaSeconds = 0
		}
	}
	scan.mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":           scan.ID,
		"target":       scan.Target,
		"start_time":   scan.StartTime.Format(time.RFC3339),
		"end_time":     "",
		"eta_seconds":  etaSeconds,
		"status":       scan.Status,
		"phase":        scan.Phase,
		"progress":     progress,
		"findings":     findings,
		"events":       scan.Events,
		"scan_mode":    "normal",
		"phases":       []string{"recon", "vuln_scan", "exploit", "report"},
		"preset":       "custom",
		"authenticated": scan.Credentials != nil,
	})
}

func (s *Server) handleStopScan(w http.ResponseWriter, r *http.Request, id string) {
	tenantID := s.getTenantID(r)
	if tenantID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	scan := s.scanStore.GetWithTenant(tenantID, id)
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	scan.mu.Lock()
	scan.Status = "stopped"
	scan.mu.Unlock()

	// Cancel the running scan goroutine
	if s.stopScanFn != nil {
		s.stopScanFn(id)
	}

	if s.diskStore != nil {
		scan.mu.RLock()
		ps := &store.PersistedScan{
			ID:        scan.ID,
			Target:    scan.Target,
			StartTime: scan.StartTime,
			Status:    scan.Status,
			Phase:     scan.Phase,
			Progress:  scan.Progress,
		}
		for _, f := range scan.Findings {
			ps.Findings = append(ps.Findings, store.PersistedFinding{
				ID:          f.ID,
				ScanID:      scan.ID,
				Type:        f.Type,
				Severity:    f.Severity,
				Target:      f.Target,
				Title:       f.Title,
				Description: f.Description,
				Evidence:    f.Evidence,
				MitreTags:   f.MitreTags,
				CVSS:        f.CVSS,
				Confirmed:   f.Confirmed,
				Timestamp:   f.Timestamp,
			})
		}
		scan.mu.RUnlock()
		s.diskStore.SaveScan(ps)
	}
	s.Server.Push(id, "SCAN_END", "Scan stopped by user")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func (s *Server) handleRetest(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID := s.getTenantID(r)
	orig := s.scanStore.GetWithTenant(tenantID, id)
	if orig == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	scanID := uuid.New()
	scan := &ScanSession{
		ID:        scanID,
		Target:    orig.Target,
		StartTime: time.Now(),
		Status:    "queued",
		Phase:     "initializing",
		Progress:  0,
		Findings:  make([]Finding, 0),
		Events:    make([]Event, 0),
	}
	s.scanStore.AddWithTenant(tenantID, scan)
	s.Server.Push(scanID, "SCAN_START", fmt.Sprintf("Retest queued for target: %s", orig.Target))

	if fn := s.getRunScanFn(); fn != nil {
		phases := []string{"recon", "scan", "exploit", "report"}
		go func() {
			fn(scanID, orig.Target, phases)
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "retest_queued",
		"scan_id":     scanID,
		"target":      orig.Target,
		"original_id": id,
	})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request, id string) {
	tenantID := s.getTenantID(r)
	scan := s.scanStore.GetWithTenant(tenantID, id)
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	scan.mu.RLock()
	findings := make([]FindingJSON, 0, len(scan.Findings))
	for _, f := range scan.Findings {
		status := "open"
		ep := f.Target
		if e, ok := f.Evidence["endpoint"]; ok && e != "" {
			ep = e
		}
		findings = append(findings, FindingJSON{
			ID:           f.ID,
			Title:        f.Title,
			Severity:     f.Severity,
			Endpoint:     ep,
			Status:       status,
			DiscoveredAt: f.Timestamp.Format(time.RFC3339),
			CVSSScore:    f.CVSS,
			Confirmed:    f.Confirmed,
		})
	}
	scan.mu.RUnlock()
	json.NewEncoder(w).Encode(findings)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, id string) {
	tenantID := s.getTenantID(r)
	scan := s.scanStore.GetWithTenant(tenantID, id)
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	scan.mu.RLock()
	allFindings := make([]Finding, len(scan.Findings))
	copy(allFindings, scan.Findings)
	scan.mu.RUnlock()
	report := map[string]interface{}{
		"scan_id":    scan.ID,
		"target":     scan.Target,
		"status":     scan.Status,
		"findings":   allFindings,
		"start_time": scan.StartTime,
		"total":      len(allFindings),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func (s *Server) handleReportJSON(w http.ResponseWriter, r *http.Request, id string) {
	tenantID := s.getTenantID(r)
	scan := s.scanStore.GetWithTenant(tenantID, id)
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	scan.mu.RLock()
	allFindings := make([]Finding, len(scan.Findings))
	copy(allFindings, scan.Findings)
	scan.mu.RUnlock()
	data := map[string]interface{}{
		"scan_id":    scan.ID,
		"target":     scan.Target,
		"status":     scan.Status,
		"phase":      scan.Phase,
		"progress":   scan.Progress,
		"start_time": scan.StartTime,
		"findings":   allFindings,
		"total":      len(allFindings),
	}
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.json\"", id))
	w.Write(jsonBytes)
}

func (s *Server) handleReportPDF(w http.ResponseWriter, r *http.Request, id string) {
	tenantID := s.getTenantID(r)
	scan := s.scanStore.GetWithTenant(tenantID, id)
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	scan.mu.RLock()
	rpt := scanToReport(scan)
	scan.mu.RUnlock()
	gen := report.NewPDFGenerator(rpt, report.ReportConfig{Format: "pdf"})
	pdfData, err := gen.Generate()
	if err != nil {
		http.Error(w, "report generation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.pdf\"", id))
	w.Write(pdfData)
}

func (s *Server) handleReportText(w http.ResponseWriter, r *http.Request, id string) {
	tenantID := s.getTenantID(r)
	scan := s.scanStore.GetWithTenant(tenantID, id)
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	scan.mu.RLock()
	var b strings.Builder
	b.WriteString(fmt.Sprintf("=== ARES Scan Report ===\n"))
	b.WriteString(fmt.Sprintf("Scan ID: %s\n", scan.ID))
	b.WriteString(fmt.Sprintf("Target: %s\n", scan.Target))
	b.WriteString(fmt.Sprintf("Status: %s\n", scan.Status))
	b.WriteString(fmt.Sprintf("Duration: %s\n", time.Since(scan.StartTime).Round(time.Second)))
	b.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Total Findings: %d\n", len(scan.Findings)))
	critical, high, medium, low := 0, 0, 0, 0
	for _, f := range scan.Findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}
	b.WriteString(fmt.Sprintf("  Critical: %d\n", critical))
	b.WriteString(fmt.Sprintf("  High:     %d\n", high))
	b.WriteString(fmt.Sprintf("  Medium:   %d\n", medium))
	b.WriteString(fmt.Sprintf("  Low:      %d\n\n", low))
	for i, f := range scan.Findings {
		b.WriteString(fmt.Sprintf("[%d] %s\n", i+1, f.Title))
		b.WriteString(fmt.Sprintf("    Severity: %s\n", f.Severity))
		ep := f.Target
		if e, ok := f.Evidence["endpoint"]; ok && e != "" {
			ep = e
		}
		b.WriteString(fmt.Sprintf("    Endpoint: %s\n", ep))
		if f.Description != "" {
			b.WriteString(fmt.Sprintf("    Description: %s\n", f.Description))
		}
		b.WriteString("\n")
	}
	scan.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (s *Server) handleNote(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Note) > 10000 {
		http.Error(w, "note too long", http.StatusBadRequest)
		return
	}
	s.Server.Push(id, "NOTE", html.EscapeString(req.Note))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "note added"})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !isAllowedOrigin(origin, s.cfg.CORSOrigins) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}
	tenantID := s.getTenantID(r)
	scan := s.scanStore.GetWithTenant(tenantID, id)
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	scan.mu.RLock()
	events := make([]Event, len(scan.Events))
	copy(events, scan.Events)
	scan.mu.RUnlock()
	for _, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
	}
	flusher.Flush()
	<-r.Context().Done()
}

func (s *Server) handleGraphExport(w http.ResponseWriter, r *http.Request) {
	if s.attackGraph == nil {
		http.Error(w, "no graph data available", http.StatusNotFound)
		return
	}
	export := s.attackGraph.Export()
	chains := s.attackGraph.TopAttackChains(10)
	export.Chains = chains
	export.Statistics.ChainCount = len(chains)
	if len(chains) > 0 {
		export.Statistics.MaxChainScore = chains[0].Score
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(export)
}

func (s *Server) handleGraphDOT(w http.ResponseWriter, r *http.Request) {
	if s.attackGraph == nil {
		http.Error(w, "no graph data available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/vnd.graphviz")
	w.Write([]byte(s.attackGraph.ExportDOT()))
}

func (s *Server) handleGraphMermaid(w http.ResponseWriter, r *http.Request) {
	if s.attackGraph == nil {
		http.Error(w, "no graph data available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(s.attackGraph.ExportMermaid()))
}

func (s *Server) handleGraphChains(w http.ResponseWriter, r *http.Request) {
	if s.attackGraph == nil {
		http.Error(w, "no graph data available", http.StatusNotFound)
		return
	}
	maxChains := 10
	if n := r.URL.Query().Get("limit"); n != "" {
		if _, err := fmt.Sscanf(n, "%d", &maxChains); err != nil {
			maxChains = 10
		}
	}
	chains := s.attackGraph.TopAttackChains(maxChains)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chains)
}

func (s *Server) handleAttackPaths(w http.ResponseWriter, r *http.Request) {
	if s.pathSimulator == nil || s.attackGraph == nil {
		http.Error(w, "attack path simulator not available", http.StatusNotFound)
		return
	}

	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")

	var results []attackpath.AttackPath
	switch {
	case start != "" && end != "":
		results = s.pathSimulator.FindAllPaths(start, end)
	case r.URL.Query().Get("mode") == "critical":
		results = s.pathSimulator.FindCriticalPaths()
	case r.URL.Query().Get("mode") == "shortest":
		results = s.pathSimulator.ShortestPathToCrownJewels()
	default:
		results = s.pathSimulator.FindCriticalPaths()
	}

	w.Header().Set("Content-Type", "application/json")
	if results == nil {
		json.NewEncoder(w).Encode([]attackpath.AttackPath{})
		return
	}
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleAttackPathReport(w http.ResponseWriter, r *http.Request) {
	if s.pathSimulator == nil || s.attackGraph == nil {
		http.Error(w, "attack path simulator not available", http.StatusNotFound)
		return
	}

	title := r.URL.Query().Get("title")
	if title == "" {
		title = "Attack Path Analysis"
	}

	format := r.URL.Query().Get("format")
	report := s.pathSimulator.GenerateReport(title)

	var output string
	switch format {
	case "markdown":
		output = report.Markdown()
		w.Header().Set("Content-Type", "text/markdown")
	case "executive":
		output = report.ExecutiveSummary()
		w.Header().Set("Content-Type", "text/plain")
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(report)
		return
	}

	w.Write([]byte(output))
}

func (s *Server) handleBlastRadius(w http.ResponseWriter, r *http.Request) {
	if s.pathSimulator == nil || s.attackGraph == nil {
		http.Error(w, "attack path simulator not available", http.StatusNotFound)
		return
	}

	nodeID := r.URL.Query().Get("node")
	if nodeID == "" {
		http.Error(w, "node query parameter required", http.StatusBadRequest)
		return
	}

	depth := 3
	if d := r.URL.Query().Get("depth"); d != "" {
		fmt.Sscanf(d, "%d", &depth)
	}

	result := s.pathSimulator.CalculateBlastRadius(nodeID, depth)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) verifyGitHubSignature(payload []byte, signatureHeader string, secret string) bool {
	if secret == "" {
		return true
	}
	if !strings.HasPrefix(signatureHeader, "sha256=") {
		return false
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(signatureHeader, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := mac.Sum(nil)
	return hmac.Equal(sig, expected)
}

var webhookRateLimiter = ratelimit.NewRateLimiter(10, 10)

func (s *Server) handleTriggerWebhook(w http.ResponseWriter, r *http.Request) {
	if !webhookRateLimiter.Allow(r.RemoteAddr) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	webhookSecret := os.Getenv("ARES_WEBHOOK_SECRET")
	sigHeader := r.Header.Get("X-Hub-Signature-256")
	if webhookSecret != "" && !s.verifyGitHubSignature(body, sigHeader, webhookSecret) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		eventType = r.Header.Get("X-Event-Type")
	}

	metadata := make(map[string]string)
	metadata["event_type"] = eventType
	metadata["content_type"] = r.Header.Get("Content-Type")

	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "triggered",
		"target": target,
	})
}

func (s *Server) handleTriggerManagement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "trigger management not available"})
}

func (s *Server) handleRemediationGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.remediationGen == nil {
		s.remediationGen = coderemediation.NewFixGenerator()
	}

	var req struct {
		FindingType string `json:"finding_type"`
		Language    string `json:"language"`
		Context     string `json:"context"`
		FilePath    string `json:"file_path"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if !requireJSONContentType(w, r) {
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.FindingType == "" || req.Language == "" {
		http.Error(w, "finding_type and language required", http.StatusBadRequest)
		return
	}

	fixReq := coderemediation.FixRequest{
		FindingType: req.FindingType,
		Language:    req.Language,
		Context:     req.Context,
		FilePath:    req.FilePath,
	}
	snippet := s.remediationGen.GenerateFix(fixReq)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snippet)
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys := s.apiKeyManager.List()
	type keyOut struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Prefix    string    `json:"prefix"`
		Role      string    `json:"role"`
		CreatedAt time.Time `json:"created_at"`
		LastUsed  time.Time `json:"last_used,omitempty"`
		IsActive  bool      `json:"is_active"`
	}
	out := make([]keyOut, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyOut{
			ID:        k.ID,
			Name:      k.Name,
			Prefix:    k.Prefix,
			Role:      string(k.Role),
			CreatedAt: k.CreatedAt,
			LastUsed:  k.LastUsed,
			IsActive:  k.IsActive,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if !requireJSONContentType(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	role := auth.UserRole(req.Role)
	if role == "" {
		role = auth.RoleViewer
	}
	if role != auth.RoleAdmin && role != auth.RoleOperator && role != auth.RoleViewer {
		http.Error(w, "invalid role: must be admin, operator, or viewer", http.StatusBadRequest)
		return
	}
	key, rawToken, err := s.apiKeyManager.Create(req.Name, role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         key.ID,
		"name":       key.Name,
		"prefix":     key.Prefix,
		"role":       key.Role,
		"api_key":    rawToken,
		"created_at": key.CreatedAt,
		"is_active":  key.IsActive,
	})
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.apiKeyManager.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// ─── Usage Tracking ──────────────────────────────────────────────────────────

type UsageData struct {
	mu             sync.RWMutex
	totalScans     int
	totalFindings  int
	criticalCount  int
	highCount      int
	mediumCount    int
	lowCount       int
	scanStartTimes map[string]time.Time
}

type UsageTracker struct {
	tenants map[string]*UsageData
	mu      sync.RWMutex
}

func NewUsageTracker() *UsageTracker {
	return &UsageTracker{
		tenants: make(map[string]*UsageData),
	}
}

func (ut *UsageTracker) forTenant(tenantID string) *UsageData {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	if ut.tenants[tenantID] == nil {
		ut.tenants[tenantID] = &UsageData{
			scanStartTimes: make(map[string]time.Time),
		}
	}
	return ut.tenants[tenantID]
}

func (ut *UsageTracker) RecordScanStart(tenantID, scanID string) {
	d := ut.forTenant(tenantID)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.totalScans++
	d.scanStartTimes[scanID] = time.Now()
}

func (ut *UsageTracker) RecordFinding(tenantID string, severity string) {
	d := ut.forTenant(tenantID)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.totalFindings++
	switch strings.ToLower(severity) {
	case "critical":
		d.criticalCount++
	case "high":
		d.highCount++
	case "medium":
		d.mediumCount++
	case "low":
		d.lowCount++
	}
}

func (ut *UsageTracker) Snapshot(tenantID string) map[string]interface{} {
	d := ut.forTenant(tenantID)
	d.mu.RLock()
	defer d.mu.RUnlock()
	return map[string]interface{}{
		"total_scans":    d.totalScans,
		"total_findings": d.totalFindings,
		"critical":       d.criticalCount,
		"high":           d.highCount,
		"medium":         d.mediumCount,
		"low":            d.lowCount,
	}
}

func (s *Server) checkScanQuota(tenantID string) error {
	return nil
}

func (s *Server) handleTenantUsage(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	usage := s.usageTracker.Snapshot(tenantID)
	usage["tenant_id"] = tenantID
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(usage)
}

// ─── Notification Engine ─────────────────────────────────────────────────────

type Notification struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Message string `json:"message"`
	ScanID  string `json:"scan_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type WebhookConfig struct {
	URL     string `json:"url"`
	Secret  string `json:"secret,omitempty"`
	Channel string `json:"channel,omitempty"`
	Enabled bool   `json:"enabled"`
}

type NotificationEngine struct {
	mu            sync.Mutex
	notifications []Notification
	maxStored     int
	webhooks      []WebhookConfig
	httpClient    *http.Client
}

func NewNotificationEngine() *NotificationEngine {
	return &NotificationEngine{
		notifications: make([]Notification, 0, 100),
		maxStored:     500,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (ne *NotificationEngine) SetWebhooks(webhooks []WebhookConfig) {
	ne.mu.Lock()
	defer ne.mu.Unlock()
	ne.webhooks = webhooks
}

func (ne *NotificationEngine) Push(n Notification) {
	ne.mu.Lock()
	n.CreatedAt = time.Now()
	ne.notifications = append(ne.notifications, n)
	if len(ne.notifications) > ne.maxStored {
		ne.notifications = ne.notifications[len(ne.notifications)-ne.maxStored:]
	}
	webhooks := make([]WebhookConfig, len(ne.webhooks))
	copy(webhooks, ne.webhooks)
	ne.mu.Unlock()

	for _, w := range webhooks {
		if !w.Enabled {
			continue
		}
		ne.sendWebhook(w, n)
	}
}

func (ne *NotificationEngine) sendWebhook(wc WebhookConfig, n Notification) {
	body := map[string]interface{}{
		"text":       n.Title,
		"message":    n.Message,
		"type":       n.Type,
		"scan_id":    n.ScanID,
		"tenant_id":  n.TenantID,
		"created_at": n.CreatedAt,
	}
	if wc.Channel != "" {
		body["channel"] = wc.Channel
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, wc.URL, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if wc.Secret != "" {
		req.Header.Set("X-Webhook-Secret", wc.Secret)
	}
	ne.httpClient.Do(req)
}

func (ne *NotificationEngine) List(tenantID string, limit int) []Notification {
	ne.mu.Lock()
	defer ne.mu.Unlock()
	var out []Notification
	for i := len(ne.notifications) - 1; i >= 0; i-- {
		n := ne.notifications[i]
		if n.TenantID == "" || n.TenantID == tenantID {
			out = append(out, n)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	if out == nil {
		return []Notification{}
	}
	return out
}

func (s *Server) notifyScanComplete(scanID, tenantID, target, status string) {
	s.notificationEngine.Push(Notification{
		Type:     "scan_complete",
		Title:    fmt.Sprintf("Scan %s — %s", status, target),
		Message:  fmt.Sprintf("Scan %s completed with status: %s", scanID, status),
		ScanID:   scanID,
		TenantID: tenantID,
	})
}

func (s *Server) notifyCriticalFinding(scanID, tenantID, findingTitle string) {
	s.notificationEngine.Push(Notification{
		Type:     "critical_finding",
		Title:    "Critical finding discovered",
		Message:  fmt.Sprintf("Critical finding in scan %s: %s", scanID, findingTitle),
		ScanID:   scanID,
		TenantID: tenantID,
	})
}

func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	tenantID := s.getTenantID(r)
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	notifications := s.notificationEngine.List(tenantID, limit)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notifications)
}
