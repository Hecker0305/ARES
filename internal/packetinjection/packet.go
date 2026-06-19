package packetinjection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type ProtocolType string

const (
	ProtoTCP  ProtocolType = "tcp"
	ProtoUDP  ProtocolType = "udp"
	ProtoICMP ProtocolType = "icmp"
	ProtoHTTP ProtocolType = "http"
	ProtoDNS  ProtocolType = "dns"
	ProtoARP  ProtocolType = "arp"
)

type InjectionMode string

const (
	ModeRaw        InjectionMode = "raw"
	ModeSpoofed    InjectionMode = "spoofed"
	ModeFragmented InjectionMode = "fragmented"
	ModeMITM       InjectionMode = "mitm"
)

type PacketTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Protocol    ProtocolType      `json:"protocol"`
	Description string            `json:"description,omitempty"`
	RawHex      string            `json:"raw_hex,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
}

type InjectionResult struct {
	ID              string        `json:"id"`
	Target          string        `json:"target"`
	Protocol        ProtocolType  `json:"protocol"`
	Mode            InjectionMode `json:"mode"`
	PacketsSent     int           `json:"packets_sent"`
	PacketsReceived int           `json:"packets_received,omitempty"`
	BytesSent       int64         `json:"bytes_sent"`
	Duration        string        `json:"duration"`
	ResponseSummary string        `json:"response_summary,omitempty"`
	Error           string        `json:"error,omitempty"`
	StartedAt       time.Time     `json:"started_at"`
	CompletedAt     time.Time     `json:"completed_at"`
}

type FuzzTemplate struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

type FuzzSession struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Protocol  string    `json:"protocol"`
	Status    string    `json:"status"`
	Duration  string    `json:"duration"`
	CreatedAt time.Time `json:"created_at"`
}

type MITMRelay struct {
	mu            sync.RWMutex
	ID            string    `json:"id"`
	ListenAddr    string    `json:"listen_addr"`
	TargetAddr    string    `json:"target_addr"`
	Protocol      string    `json:"protocol"`
	Active        bool      `json:"active"`
	StartedAt     time.Time `json:"started_at"`
	BytesCaptured int64     `json:"bytes_captured"`
}

type Engine struct {
	mu            sync.RWMutex
	templates     []PacketTemplate
	results       []InjectionResult
	relays        []*MITMRelay
	fuzzSessions  []FuzzSession
	fuzzTemplates []FuzzTemplate
	listeners     map[string]net.Listener
	relayCancel   map[string]context.CancelFunc
}

func New() *Engine {
	e := &Engine{
		listeners:   make(map[string]net.Listener),
		relayCancel: make(map[string]context.CancelFunc),
	}
	e.seedTemplates()
	e.fuzzTemplates = []FuzzTemplate{
		{ID: "http_headers", Name: "HTTP Header Fuzzing", Protocol: "http"},
		{ID: "tcp_payload", Name: "TCP Payload Fuzzing", Protocol: "tcp"},
		{ID: "udp_payload", Name: "UDP Payload Fuzzing", Protocol: "udp"},
		{ID: "dns_query", Name: "DNS Query Fuzzing", Protocol: "dns"},
	}
	return e
}

func (e *Engine) seedTemplates() {
	e.templates = []PacketTemplate{
		{ID: "syn_flood", Name: "SYN Flood", Protocol: ProtoTCP, Description: "TCP SYN flood for stress testing", RawHex: "0800271c9c2a080027d4b8e008004500003c0000000080062a8dc0a80001c0a80002001a00"},
		{ID: "icmp_flood", Name: "ICMP Echo Flood", Protocol: ProtoICMP, Description: "ICMP echo request flood", RawHex: "0800271c9c2a080027d4b8e008004500003c0000000080062a8dc0a80001c0a80002001a000800"},
		{ID: "dns_amplification", Name: "DNS Amplification", Protocol: ProtoDNS, Description: "DNS amplification attack vector", Options: map[string]string{"query_type": "ANY", "domain": "example.com"}},
		{ID: "arp_spoof", Name: "ARP Spoof", Protocol: ProtoARP, Description: "ARP cache poisoning packet", RawHex: "ffffffffffff080027d4b8e008000600010000080027d4b8e0c0a80001ffffffffffffc0a80002"},
		{ID: "http_get", Name: "HTTP GET Flood", Protocol: ProtoHTTP, Description: "HTTP GET request flood", Options: map[string]string{"path": "/", "host": "target.com"}},
	}
}

func (e *Engine) Inject(target string, proto ProtocolType, mode InjectionMode, count int, templateID string) (*InjectionResult, error) {
	started := time.Now()

	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}
	if count <= 0 {
		return nil, fmt.Errorf("count must be > 0")
	}

	result := &InjectionResult{
		ID:        uuid.New(),
		Target:    target,
		Protocol:  proto,
		Mode:      mode,
		StartedAt: started,
	}

	simCount := count
	if simCount > 10 {
		simCount = 10
	}
	var pktBytes int64
	for i := 0; i < simCount; i++ {
		pkt := buildTestPacket(proto)
		pktBytes += int64(len(pkt))
	}

	elapsed := time.Since(started)
	result.PacketsSent = simCount
	result.BytesSent = pktBytes
	result.CompletedAt = time.Now()
	result.Duration = elapsed.Round(time.Millisecond).String()

	e.mu.Lock()
	e.results = append(e.results, *result)
	e.mu.Unlock()

	return result, nil
}

func buildTestPacket(proto ProtocolType) []byte {
	switch proto {
	case ProtoTCP:
		return []byte("MOCK-TCP-PACKET-64-BYTES-MOCK-TCP-PACKET-64-BYTES-MOCK")
	case ProtoUDP:
		return []byte("MOCK-UDP-PACKET-64-BYTES-MOCK-UDP-PACKET-64-BYTES-MOCK")
	case ProtoICMP:
		return []byte("MOCK-ICMP-PACKET-64-BYTES-MOCK-ICMP-PACKET-64-BYTES")
	case ProtoHTTP:
		return []byte("GET / HTTP/1.1\r\nHost: mock\r\n\r\n")
	case ProtoDNS:
		return []byte("MOCK-DNS-QUERY-PACKET-64-BYTES-MOCK-DNS-QUERY")
	default:
		return []byte("MOCK-RAW-PACKET-64-BYTES-FOR-TESTING-PURPOSES-ONLY")
	}
}

func (e *Engine) StartMITM(listenAddr, targetAddr string) *MITMRelay {
	relay := &MITMRelay{
		ID:         uuid.New(),
		ListenAddr: listenAddr,
		TargetAddr: targetAddr,
		Protocol:   "tcp",
		Active:     true,
		StartedAt:  time.Now(),
	}

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		relay.Active = false
		e.mu.Lock()
		e.relays = append(e.relays, relay)
		e.mu.Unlock()
		return relay
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.listeners[relay.ID] = lis
	e.relayCancel[relay.ID] = cancel
	e.relays = append(e.relays, relay)
	e.mu.Unlock()

	go e.runMITMRelay(ctx, relay, lis)
	return relay
}

func (e *Engine) runMITMRelay(ctx context.Context, relay *MITMRelay, lis net.Listener) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			logger.Error("[MITM] relay panic recovered", logger.Fields{
				"panic": fmt.Sprintf("%v", r),
				"stack": string(buf[:n]),
			})
		}
	}()
	for {
		clientConn, err := lis.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		targetConn, err := net.DialTimeout("tcp", relay.TargetAddr, 10*time.Second)
		if err != nil {
			clientConn.Close()
			continue
		}

		go func(client, target net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					buf := make([]byte, 2048)
					n := runtime.Stack(buf, false)
					logger.Error("[MITM] connection relay panic", logger.Fields{
						"panic": fmt.Sprintf("%v", r),
						"stack": string(buf[:n]),
					})
				}
			}()
			defer client.Close()
			defer target.Close()

			var wg sync.WaitGroup
			wg.Add(2)
			var relayed int64

			go func() {
				defer wg.Done()
				n, _ := io.Copy(target, client)
				relayed += n
			}()
			go func() {
				defer wg.Done()
				n, _ := io.Copy(client, target)
				relayed += n
			}()

			wg.Wait()

			relay.mu.Lock()
			relay.BytesCaptured += relayed
			relay.mu.Unlock()
		}(clientConn, targetConn)
	}
}

func (e *Engine) StopMITM(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	cancel, ok := e.relayCancel[id]
	if ok {
		cancel()
		delete(e.relayCancel, id)
	}

	lis, ok := e.listeners[id]
	if ok {
		lis.Close()
		delete(e.listeners, id)
	}

	for i := range e.relays {
		if e.relays[i].ID == id {
			e.relays[i].Active = false
			return true
		}
	}
	return false
}

func (e *Engine) ListTemplates() []PacketTemplate {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.templates
}

func (e *Engine) ListResults() []InjectionResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.results
}

func (e *Engine) StartFuzz(target string, templateID string) (*FuzzSession, error) {

	parts := strings.Split(target, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("target must be in format ip:port")
	}

	var proto string
	for _, ft := range e.fuzzTemplates {
		if ft.ID == templateID {
			proto = ft.Protocol
			break
		}
	}
	if proto == "" {
		proto = "tcp"
	}

	session := &FuzzSession{
		ID:        uuid.New(),
		Target:    target,
		Protocol:  proto,
		Status:    "running",
		CreatedAt: time.Now(),
	}

	started := time.Now()
	err := e.runFuzzPython(target, proto, templateID)
	duration := time.Since(started)

	if err != nil {
		session.Status = "error"
		session.Duration = err.Error()
	} else {
		session.Status = "completed"
		session.Duration = duration.Round(time.Millisecond).String()
	}

	e.mu.Lock()
	e.fuzzSessions = append(e.fuzzSessions, *session)
	e.mu.Unlock()
	return session, nil
}

func (e *Engine) runFuzzPython(target, proto, templateID string) error {
	pythonPath := "python3"
	if p := os.Getenv("ARES_PYTHON"); p != "" {
		pythonPath = p
	}

	t2 := strings.Split(target, ":")
	scriptPath := filepath.Join("internal", "packetinjection", "fuzz.py")
	if _, err := os.Stat(scriptPath); err != nil {
		wd, _ := os.Getwd()
		scriptPath = filepath.Join(wd, "internal", "packetinjection", "fuzz.py")
	}

	templateJSON := fmt.Sprintf(`{"fuzz_uri": true, "type": "%s"}`, templateID)
	cmd := exec.Command(pythonPath, scriptPath, t2[0], t2[1], proto, templateJSON)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fuzz exec: %s: %v", string(output), err)
	}
	return nil
}

func (e *Engine) ListFuzzSessions() []FuzzSession {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]FuzzSession, len(e.fuzzSessions))
	copy(result, e.fuzzSessions)
	return result
}

func (e *Engine) ListFuzzTemplates() []FuzzTemplate {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]FuzzTemplate, len(e.fuzzTemplates))
	copy(result, e.fuzzTemplates)
	return result
}

func (e *Engine) ListRelays() []*MITMRelay {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.relays
}

func RegisterHandlers(mux *http.ServeMux, engine *Engine) {
	mux.HandleFunc("/api/packet/fuzz-templates", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(engine.ListFuzzTemplates())
	})
	mux.HandleFunc("/api/packet/fuzz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(engine.ListFuzzSessions())
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Target     string `json:"target"`
			TemplateID string `json:"template_id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		session, err := engine.StartFuzz(req.Target, req.TemplateID)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(session)
	})
	mux.HandleFunc("/api/packet/templates", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(engine.ListTemplates())
	})
	mux.HandleFunc("/api/packet/inject", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Target     string        `json:"target"`
			Protocol   ProtocolType  `json:"protocol"`
			Mode       InjectionMode `json:"mode"`
			Count      int           `json:"count"`
			TemplateID string        `json:"template_id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Count <= 0 {
			req.Count = 1
		}
		result, err := engine.Inject(req.Target, req.Protocol, req.Mode, req.Count, req.TemplateID)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("/api/packet/results", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(engine.ListResults())
	})
	mux.HandleFunc("/api/packet/mitm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(engine.ListRelays())
		case http.MethodPost:
			var req struct {
				ListenAddr string `json:"listen_addr"`
				TargetAddr string `json:"target_addr"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			if req.ListenAddr == "" {
				req.ListenAddr = "0.0.0.0:8080"
			}
			relay := engine.StartMITM(req.ListenAddr, req.TargetAddr)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(relay)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/packet/mitm/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := strings.TrimPrefix(r.URL.Path, "/api/packet/mitm/")
		if r.Method == http.MethodDelete {
			if engine.StopMITM(id) {
				json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
			} else {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			}
		}
	})
}
