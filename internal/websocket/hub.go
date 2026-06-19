package websocket

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/gorilla/websocket"
)

type Hub struct {
	clients         map[*Client]bool
	broadcast       chan []byte
	register        chan *Client
	unregister      chan *Client
	mu              sync.RWMutex
	authFn          func(r *http.Request) bool
	clientIPs       map[string]int
	ipMu            sync.Mutex
	maxClientsPerIP int
	maxClients      int
	secret          []byte
	messageHandlers map[string]func(*Client, map[string]interface{}) error
	controlMu       sync.RWMutex
	scanControl     map[string]string
}

type Client struct {
	hub      *Hub
	conn     *websocket.Conn
	send     chan []byte
	userID   string
	role     string
	lastPong time.Time
}

type ControlMessage struct {
	Type      string                 `json:"type"`
	Payload   map[string]interface{} `json:"payload,omitempty"`
	Timestamp string                 `json:"timestamp"`
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return false
		}
		allowedOrigins := os.Getenv("ARES_CORS_ALLOWED_ORIGINS")
		if allowedOrigins == "" {
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			host := u.Hostname()
			return host == "localhost" || host == "127.0.0.1" || host == "::1"
		}
		for _, a := range strings.Split(allowedOrigins, ",") {
			if origin == strings.TrimSpace(a) {
				return true
			}
		}
		return false
	},
}

func NewHub() *Hub {
	h := &Hub{
		clients:         make(map[*Client]bool),
		broadcast:       make(chan []byte, 1024),
		register:        make(chan *Client, 10),
		unregister:      make(chan *Client, 10),
		clientIPs:       make(map[string]int),
		maxClientsPerIP: 5,
		maxClients:      200,
		messageHandlers: make(map[string]func(*Client, map[string]interface{}) error),
		scanControl:     make(map[string]string),
	}
	h.registerDefaultHandlers()
	return h
}

func (h *Hub) registerDefaultHandlers() {
	h.messageHandlers["pause_scan"] = h.handlePauseScan
	h.messageHandlers["resume_scan"] = h.handleResumeScan
	h.messageHandlers["inject_hint"] = h.handleInjectHint
	h.messageHandlers["stop_scan"] = h.handleStopScan
	h.messageHandlers["get_status"] = h.handleGetStatus
}

func NewHubWithAuth(authFn func(r *http.Request) bool, secret []byte) *Hub {
	h := NewHub()
	h.authFn = authFn
	h.secret = secret
	return h
}

func (h *Hub) Run(ctx context.Context) {
	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			h.mu.Lock()
			for client := range h.clients {
				close(client.send)
			}
			h.clients = make(map[*Client]bool)
			h.mu.Unlock()
			return
		case <-cleanupTicker.C:
			h.controlMu.Lock()
			for scanID := range h.scanControl {
				delete(h.scanControl, scanID)
			}
			h.controlMu.Unlock()
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

			h.ipMu.Lock()
			h.clientIPs[client.conn.RemoteAddr().String()]++
			h.ipMu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

			h.ipMu.Lock()
			ip := client.conn.RemoteAddr().String()
			if cnt := h.clientIPs[ip]; cnt > 1 {
				h.clientIPs[ip]--
			} else {
				delete(h.clientIPs, ip)
			}
			h.ipMu.Unlock()

		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
		}
	}
}

func (h *Hub) Broadcast(eventType string, data interface{}) error {
	msg := map[string]interface{}{
		"type":      eventType,
		"timestamp": time.Now().Format(time.RFC3339),
		"data":      data,
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	h.broadcast <- payload
	return nil
}

func (h *Hub) BroadcastToRole(eventType string, data interface{}, role string) error {
	msg := map[string]interface{}{
		"type":      eventType,
		"timestamp": time.Now().Format(time.RFC3339),
		"data":      data,
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	for client := range h.clients {
		if client.role == role || client.role == "admin" {
			select {
			case client.send <- payload:
			default:
			}
		}
	}
	return nil
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.authFn == nil {
		http.Error(w, "unauthorized: no auth configured", http.StatusUnauthorized)
		return
	}
	if !h.authFn(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	h.mu.RLock()
	clientCount := len(h.clients)
	h.mu.RUnlock()
	if clientCount >= h.maxClients {
		http.Error(w, "maximum number of connected clients reached", http.StatusServiceUnavailable)
		return
	}

	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		http.Error(w, "origin required", http.StatusForbidden)
		return
	}
	allowedOrigins := os.Getenv("ARES_CORS_ALLOWED_ORIGINS")
	if allowedOrigins != "" {
		found := false
		for _, a := range strings.Split(allowedOrigins, ",") {
			if origin == strings.TrimSpace(a) {
				found = true
				break
			}
		}
		if !found && !strings.HasPrefix(origin, "http://localhost") && !strings.HasPrefix(origin, "https://localhost") {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
	} else if !strings.HasPrefix(origin, "http://localhost") && !strings.HasPrefix(origin, "https://localhost") {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	h.ipMu.Lock()
	if h.clientIPs[host] >= h.maxClientsPerIP {
		h.ipMu.Unlock()
		http.Error(w, "too many connections from this IP", http.StatusTooManyRequests)
		return
	}
	h.ipMu.Unlock()

	var userID, role string
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	if token == "" || !verifyTokenSignature(token, h.secret) {
		http.Error(w, "unauthorized: invalid token", http.StatusUnauthorized)
		return
	}
	claims := parseTokenClaims(token)
	if claims == nil {
		http.Error(w, "unauthorized: invalid claims", http.StatusUnauthorized)
		return
	}
	if sub, ok := claims["sub"].(string); ok {
		userID = sub
	}
	if roleVal, ok := claims["role"].(string); ok {
		role = roleVal
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error("[WebSocket] Upgrade failed", logger.Fields{"error": err.Error(), "remote": r.RemoteAddr, "origin": r.Header.Get("Origin"), "method": r.Method, "url": r.URL.String()})
		http.Error(w, "Failed to upgrade to WebSocket", http.StatusInternalServerError)
		return
	}

	client := &Client{
		hub:      h,
		conn:     conn,
		send:     make(chan []byte, 256),
		userID:   userID,
		role:     role,
		lastPong: time.Now(),
	}

	h.register <- client

	go client.writePump()
	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(65536)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.lastPong = time.Now()
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Error(fmt.Sprintf("[WebSocket] Unexpected close: %v", err))
			}
			break
		}

		if len(message) > 65536 {
			logger.Info(fmt.Sprintf("[WebSocket] Message too large (%d bytes), dropping", len(message)))
			continue
		}

		if time.Since(c.lastPong) > 120*time.Second {
			logger.Info("[WebSocket] Client heartbeat timeout, disconnecting")
			break
		}

		var msg ControlMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			logger.Error(fmt.Sprintf("[WebSocket] Invalid message format: %v", err))
			continue
		}

		c.hub.controlMu.RLock()
		handler, ok := c.hub.messageHandlers[msg.Type]
		c.hub.controlMu.RUnlock()

		if ok {
			if err := handler(c, msg.Payload); err != nil {
				logger.Error(fmt.Sprintf("[WebSocket] Handler error for %s: %v", msg.Type, err))
				c.hub.sendError(c, msg.Type, err.Error())
			}
		} else {
			logger.Info(fmt.Sprintf("[WebSocket] Unknown message type: %s", msg.Type))
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (h *Hub) ClientsCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *Hub) Stats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return map[string]interface{}{
		"connected_clients": len(h.clients),
	}
}

func parseTokenClaims(token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	payload := parts[1]
	if rem := len(payload) % 4; rem > 0 {
		payload += strings.Repeat("=", 4-rem)
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil
	}

	return claims
}

func verifyTokenSignature(token string, secret []byte) bool {
	if secret == nil {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	provided := parts[2]
	if hmac.Equal([]byte(provided), []byte(expected)) {
		return true
	}
	providedPadded := provided
	if rem := len(providedPadded) % 4; rem > 0 {
		providedPadded += strings.Repeat("=", 4-rem)
	}
	decoded, err := base64.StdEncoding.DecodeString(providedPadded)
	if err != nil {
		return false
	}
	reEncoded := base64.RawURLEncoding.EncodeToString(decoded)
	return hmac.Equal([]byte(reEncoded), []byte(expected))
}

func (h *Hub) handlePauseScan(c *Client, payload map[string]interface{}) error {
	if c.role != "admin" && c.role != "operator" {
		return fmt.Errorf("forbidden: insufficient permissions")
	}
	scanID, _ := payload["scan_id"].(string)
	if scanID == "" {
		return fmt.Errorf("scan_id required")
	}

	h.controlMu.Lock()
	h.scanControl[scanID] = "paused"
	h.controlMu.Unlock()

	logger.Info(fmt.Sprintf("[WebSocket] Scan %s paused by user %s", scanID, c.userID))

	resp := ControlMessage{
		Type:      "scan_paused",
		Payload:   map[string]interface{}{"scan_id": scanID, "status": "paused"},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal pause response: %v", err)
	}
	h.broadcast <- data

	return nil
}

func (h *Hub) handleResumeScan(c *Client, payload map[string]interface{}) error {
	if c.role != "admin" && c.role != "operator" {
		return fmt.Errorf("forbidden: insufficient permissions")
	}
	scanID, _ := payload["scan_id"].(string)
	if scanID == "" {
		return fmt.Errorf("scan_id required")
	}

	h.controlMu.Lock()
	h.scanControl[scanID] = "running"
	h.controlMu.Unlock()

	logger.Info(fmt.Sprintf("[WebSocket] Scan %s resumed by user %s", scanID, c.userID))

	resp := ControlMessage{
		Type:      "scan_resumed",
		Payload:   map[string]interface{}{"scan_id": scanID, "status": "running"},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal resume response: %v", err)
	}
	h.broadcast <- data

	return nil
}

func (h *Hub) handleInjectHint(c *Client, payload map[string]interface{}) error {
	scanID, _ := payload["scan_id"].(string)
	hint, _ := payload["hint"].(string)
	if scanID == "" || hint == "" {
		return fmt.Errorf("scan_id and hint required")
	}

	logger.Info(fmt.Sprintf("[WebSocket] Hint injected for scan %s by user %s: %s", scanID, c.userID, hint))

	resp := ControlMessage{
		Type:      "hint_injected",
		Payload:   map[string]interface{}{"scan_id": scanID, "hint": hint},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal hint response: %v", err)
	}
	h.broadcast <- data

	return nil
}

func (h *Hub) handleStopScan(c *Client, payload map[string]interface{}) error {
	if c.role != "admin" && c.role != "operator" {
		return fmt.Errorf("forbidden: insufficient permissions")
	}
	scanID, _ := payload["scan_id"].(string)
	if scanID == "" {
		return fmt.Errorf("scan_id required")
	}

	h.controlMu.Lock()
	h.scanControl[scanID] = "stopped"
	h.controlMu.Unlock()

	logger.Info(fmt.Sprintf("[WebSocket] Scan %s stopped by user %s", scanID, c.userID))

	resp := ControlMessage{
		Type:      "scan_stopped",
		Payload:   map[string]interface{}{"scan_id": scanID, "status": "stopped"},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal stop response: %v", err)
	}
	h.broadcast <- data

	return nil
}

func (h *Hub) handleGetStatus(c *Client, payload map[string]interface{}) error {
	scanID, _ := payload["scan_id"].(string)

	h.controlMu.RLock()
	status := h.scanControl[scanID]
	h.controlMu.RUnlock()

	if status == "" {
		status = "unknown"
	}

	resp := ControlMessage{
		Type:      "scan_status",
		Payload:   map[string]interface{}{"scan_id": scanID, "status": status},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal status response: %v", err)
	}
	c.send <- data

	return nil
}

func (h *Hub) GetScanStatus(scanID string) string {
	h.controlMu.RLock()
	defer h.controlMu.RUnlock()
	return h.scanControl[scanID]
}

func (h *Hub) SetScanStatus(scanID, status string) {
	h.controlMu.Lock()
	defer h.controlMu.Unlock()
	h.scanControl[scanID] = status
}

func (h *Hub) sendError(c *Client, messageType, errMsg string) {
	resp := ControlMessage{
		Type:      "error",
		Payload:   map[string]interface{}{"type": messageType, "error": errMsg},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	data, err := json.Marshal(resp)
	if err != nil {
		logger.Error(fmt.Sprintf("[WebSocket] failed to marshal error response: %v", err))
		return
	}
	select {
	case c.send <- data:
	default:
	}
}

func (h *Hub) BroadcastControl(scanID, eventType string, data map[string]interface{}) error {
	msg := ControlMessage{
		Type:      eventType,
		Payload:   data,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	if data == nil {
		msg.Payload = make(map[string]interface{})
	}
	msg.Payload["scan_id"] = scanID

	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	h.broadcast <- payload
	return nil
}
