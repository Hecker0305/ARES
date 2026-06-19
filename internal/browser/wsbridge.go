package browser

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"

	"net/url"

	"github.com/ares/engine/internal/security"
	"github.com/gorilla/websocket"
)

type WSBridge struct {
	wsPort    int
	jsPort    int
	mu        sync.RWMutex
	connected bool
	browser   *Browser
	authToken string
	tlsCert   string
	tlsKey    string
}

func NewWSBridge(wsPort, jsPort int, browser *Browser) *WSBridge {
	return NewWSBridgeWithTLS(wsPort, jsPort, browser, "", "")
}

func NewWSBridgeWithTLS(wsPort, jsPort int, browser *Browser, tlsCert, tlsKey string) *WSBridge {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		logger.Error(fmt.Sprintf("[WSBridge] CRITICAL: crypto/rand failed: %v, refusing to start without secure auth token", err))
		return nil
	}
	return &WSBridge{
		wsPort:    wsPort,
		jsPort:    jsPort,
		connected: false,
		browser:   browser,
		authToken: hex.EncodeToString(b),
		tlsCert:   tlsCert,
		tlsKey:    tlsKey,
	}
}

func (b *WSBridge) listenAndServe(addr string, handler http.Handler) error {
	cert, err := b.getTLSCertificate()
	if err != nil {
		return fmt.Errorf("failed to get TLS certificate: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	logger.Info(fmt.Sprintf("[WSBridge] TLS enabled on %s", addr))
	return http.Serve(listener, handler)
}

func (b *WSBridge) getTLSCertificate() (tls.Certificate, error) {
	if b.tlsCert != "" && b.tlsKey != "" {
		return tls.LoadX509KeyPair(b.tlsCert, b.tlsKey)
	}
	if os.Getenv("ARES_ALLOW_SELFSIGNED") != "true" && os.Getenv("ARES_WS_SELFSIGNED") != "true" {
		return tls.Certificate{}, fmt.Errorf("self-signed certificates not allowed: set ARES_ALLOW_SELFSIGNED=true or ARES_WS_SELFSIGNED=true to enable")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ARES WSBridge"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "ares.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func (b *WSBridge) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}
		if token == "" || token != b.authToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (b *WSBridge) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, bridgeHTML)
	})
	mux.HandleFunc("/inject", b.authMiddleware(b.handleInject))
	mux.HandleFunc("/screenshot", b.authMiddleware(b.handleScreenshot))
	mux.HandleFunc("/evaluate", b.authMiddleware(b.handleEvaluate))
	mux.HandleFunc("/session_cookies", b.authMiddleware(b.handleSessionCookies))
	addr := fmt.Sprintf(":%d", b.jsPort)
	logger.Info(fmt.Sprintf("[WSBridge] Bridge server on %s (auth enabled)", addr))
	return b.listenAndServe(addr, mux)
}

func allowedScripts() map[string]bool {
	return map[string]bool{
		"ares_inject.js":    true,
		"ares_content.js":   true,
		"ares_discovery.js": true,
	}
}

func (b *WSBridge) handleInject(w http.ResponseWriter, r *http.Request) {
	script := r.URL.Query().Get("script")
	if script == "" {
		script = "ares_inject.js"
	}
	script = filepath.Base(script)
	if !allowedScripts()[script] {
		http.Error(w, "script not allowed", http.StatusForbidden)
		return
	}
	data, err := os.ReadFile(filepath.Join("tools", "pageagent", script))
	if err != nil {
		data = []byte(aresInjectScript)
	}
	w.Header().Set("Content-Type", "application/javascript")
	w.Write(data)
}

func (b *WSBridge) handleScreenshot(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("url")
	if urlParam == "" {
		http.Error(w, "url required", 400)
		return
	}
	if _, err := security.SanitizeURL(urlParam); err != nil {
		http.Error(w, "invalid url", 400)
		return
	}
	if b.browser == nil {
		http.Error(w, "no browser available", 500)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	data, err := b.browser.Screenshot(ctx, urlParam)
	if err != nil {
		http.Error(w, "screenshot failed", 500)
		return
	}
	path, err := b.UploadScreenshot(data)
	if err != nil {
		http.Error(w, "save failed", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{
		"url":    urlParam,
		"path":   path,
		"size":   fmt.Sprintf("%d bytes", len(data)),
		"status": "screenshot saved",
	}
	json.NewEncoder(w).Encode(resp)
}

func (b *WSBridge) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	var req struct {
		Script string `json:"script"`
		TabID  string `json:"tab_id"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if len(req.Script) > 10000 {
		http.Error(w, "script too long", 400)
		return
	}
	if req.URL != "" {
		if _, err := security.SanitizeURL(req.URL); err != nil {
			http.Error(w, "invalid url", 400)
			return
		}
	}
	var result string
	if b.browser != nil {
		ctx := r.Context()
		if req.URL != "" {
			_, navErr := b.browser.Navigate(ctx, req.URL)
			if navErr != nil {
				result = fmt.Sprintf("navigate error: %v", navErr)
			}
		}
		if req.Script != "" {
			evalResult, evalErr := b.browser.Evaluate(ctx, req.Script)
			if evalErr != nil {
				result = fmt.Sprintf("evaluate error: %v", evalErr)
			} else {
				result = evalResult
			}
		}
	} else {
		result = "no browser available"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"tab_id": req.TabID,
		"result": result,
		"status": "evaluated",
	})
}

func (b *WSBridge) handleSessionCookies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "cookie access disabled: requires explicit authorization",
		"cookies": []string{},
	})
}

func (b *WSBridge) StartWSListener() error {
	addr := fmt.Sprintf(":%d", b.wsPort)
	logger.Info(fmt.Sprintf("[WSBridge] WebSocket listener on %s", addr))
	return b.listenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			http.NotFound(w, r)
			return
		}
		token := r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}
		if token == "" {
			http.Error(w, "unauthorized: token required in Authorization header", http.StatusUnauthorized)
			return
		}
		if token != b.authToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		b.handleWSConn(w, r)
	}))
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return false
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	},
}

func (b *WSBridge) handleWSConn(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	b.mu.Lock()
	b.connected = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.connected = false
		b.mu.Unlock()
	}()
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if wsMsg := ParseAgentMessage(string(msg)); wsMsg != nil {
			ack, _ := json.Marshal(map[string]string{"type": "ack", "id": wsMsg.ID})
			conn.WriteMessage(websocket.TextMessage, ack)
		}
	}
}

func (b *WSBridge) UploadScreenshot(data []byte) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	filename := uuid.New()
	tmpDir := os.TempDir()
	path := filepath.Join(tmpDir, filename)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", fmt.Errorf("write screenshot: %w", err)
	}
	return path, nil
}

func buildWSTextFrame(payload string) []byte {
	l := len(payload)
	frameLen := 2 + l
	if l >= 126 && l < 65536 {
		frameLen = 4 + l
	} else if l >= 65536 {
		frameLen = 10 + l
	}
	frame := make([]byte, 0, frameLen)
	frame = append(frame, 0x81)
	switch {
	case l < 126:
		frame = append(frame, byte(l))
	case l < 65536:
		frame = append(frame, 126, byte(l>>8), byte(l))
	default:
		frame = append(frame, 127)
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(l>>(8*i)))
		}
	}
	frame = append(frame, []byte(payload)...)
	return frame
}

func (b *WSBridge) IsConnected() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.connected
}

func (b *WSBridge) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.connected = false
	return nil
}

func ParseAgentMessage(data string) *AgentMessage {
	if !strings.Contains(data, `"type"`) && !strings.Contains(data, `"action"`) {
		return nil
	}
	var msg AgentMessage
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return nil
	}
	return &msg
}

type AgentMessage struct {
	Type   string `json:"type"`
	ID     string `json:"id,omitempty"`
	Action string `json:"action,omitempty"`
	Script string `json:"script,omitempty"`
	Code   string `json:"code,omitempty"`
	URL    string `json:"url,omitempty"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
	TabID  string `json:"tab_id,omitempty"`
}

func WSMessage(msg string, data any) string {
	b, _ := json.Marshal(map[string]any{"msg": msg, "data": data})
	return string(b)
}

const bridgeHTML = `<!DOCTYPE html>
<html><head><title>Ares WS Bridge</title></head>
<body>
<h2>Ares Chrome Extension Bridge</h2>
<p>Auth token configured. Set Authorization: Bearer TOKEN header.</p>
</body></html>`

const aresInjectScript = `(function(){
    var endpoints=[];
    document.querySelectorAll('a[href],form[action]').forEach(function(el){
        var h=el.href||el.action;
        if(h&&h!=='#'&&!h.startsWith('javascript'))endpoints.push(h);
    });
    var scripts=[];
    document.querySelectorAll('script[src]').forEach(function(s){scripts.push(s.src);});
    return JSON.stringify({links:Array.from(new Set(endpoints)).slice(0,50),title:document.title,forms:document.querySelectorAll('form').length,scripts:scripts});
})();`
