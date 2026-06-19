package webserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Event struct {
	Timestamp string `json:"ts"`
	ScanID    string `json:"scan_id"`
	Type      string `json:"type"`
	Message   string `json:"message"`
}

type SSEClient struct {
	Ch   chan Event
	Done chan struct{}
}

type HealthState struct {
	Ready     bool
	Live      bool
	LastError string
	StartTime time.Time
}

type Server struct {
	mu            sync.RWMutex
	clients       map[*SSEClient]struct{}
	events        []Event
	port          int
	httpSrv       *http.Server
	health        HealthState
	stopOnce      sync.Once
	authTokenHash string
}

func New(port int, authToken string) *Server {
	hash := sha256.Sum256([]byte(authToken))
	return &Server{
		clients:       make(map[*SSEClient]struct{}),
		port:          port,
		authTokenHash: hex.EncodeToString(hash[:]),
		health: HealthState{
			Ready:     false,
			Live:      true,
			StartTime: time.Now(),
		},
	}
}

func (s *Server) Start() {
	s.mu.Lock()
	s.health.Ready = true
	addr := fmt.Sprintf(":%d", s.port)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.health)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		cl := &SSEClient{Ch: make(chan Event, 64), Done: make(chan struct{})}
		s.RegisterClient(cl)
		defer s.UnregisterClient(cl)
		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-cl.Ch:
				if !ok {
					return
				}
				data, _ := json.Marshal(ev)
				fmt.Fprintf(w, "data: %s\n\n", data)
				w.(http.Flusher).Flush()
			}
		}
	})
	s.httpSrv = &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	s.mu.Unlock()
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.mu.Lock()
			s.health.Live = false
			s.health.LastError = err.Error()
			s.mu.Unlock()
		}
	}()
}

func (s *Server) Stop(timeout time.Duration) {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.health.Ready = false
		s.mu.Unlock()
		if s.httpSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if err := s.httpSrv.Shutdown(ctx); err != nil {
				s.mu.Lock()
				s.health.LastError = err.Error()
				s.mu.Unlock()
			}
		}
	})
}

func (s *Server) Push(scanID, evType, message string) {
	ev := Event{
		Timestamp: time.Now().Format(time.RFC3339),
		ScanID:    scanID,
		Type:      evType,
		Message:   message,
	}
	s.mu.Lock()
	s.events = append(s.events, ev)
	if len(s.events) > 1000 {
		s.events = s.events[len(s.events)-1000:]
	}
	for cl := range s.clients {
		select {
		case <-cl.Done:
			continue
		default:
		}
		select {
		case cl.Ch <- ev:
		default:
		}
	}
	s.mu.Unlock()
}

func (s *Server) RegisterClient(cl *SSEClient) {
	s.mu.Lock()
	s.clients[cl] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) UnregisterClient(cl *SSEClient) {
	s.mu.Lock()
	delete(s.clients, cl)
	s.mu.Unlock()
}
