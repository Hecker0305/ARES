package mythic

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/gorilla/websocket"
)

type MythicEvent struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type MythicWSClient struct {
	mu             sync.Mutex
	conn           *websocket.Conn
	connected      bool
	eventHandler   func(event MythicEvent)
	stopCh         chan struct{}
	reconnectDelay time.Duration
}

type MythicEventHandler func(event MythicEvent)

func (e *MythicEngine) ConnectWebSocket() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.wsConnected {
		return nil
	}

	wsURL := e.config.WSSEndpoint
	if wsURL == "" {
		wsURL = fmt.Sprintf("wss://%s/ws", e.config.ServerURL)
	}

	header := http.Header{}
	header.Set("Authorization", "Bearer "+e.apiToken)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}

	e.wsConnected = true
	logger.Info(fmt.Sprintf("[Mythic] WebSocket connected: %s", wsURL))
	_ = conn
	return nil
}

func (e *MythicEngine) DisconnectWebSocket() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.wsConnected = false
}

func (e *MythicEngine) StartMonitoring(handler func(event MythicEvent)) {
	e.mu.Lock()
	wsURL := e.config.WSSEndpoint
	if wsURL == "" {
		wsURL = fmt.Sprintf("wss://%s/ws", e.config.ServerURL)
	}
	token := e.apiToken
	e.mu.Unlock()

	client := &MythicWSClient{
		eventHandler:   handler,
		stopCh:         make(chan struct{}),
		reconnectDelay: 5 * time.Second,
	}

	go client.runLoop(wsURL, token)
}

func (c *MythicWSClient) runLoop(wsURL, token string) {
	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		header := http.Header{}
		header.Set("Authorization", "Bearer "+token)

		conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
		if err != nil {
			log.Printf("[Mythic WS] connect failed: %v (retry in %s)", err, c.reconnectDelay)
			time.Sleep(c.reconnectDelay)
			continue
		}

		c.mu.Lock()
		c.conn = conn
		c.connected = true
		c.mu.Unlock()

		c.readLoop()

		c.mu.Lock()
		c.connected = false
		c.conn = nil
		c.mu.Unlock()

		time.Sleep(c.reconnectDelay)
	}
}

func (c *MythicWSClient) readLoop() {
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			logger.Error(fmt.Sprintf("[Mythic WS] read error: %v", err))
			return
		}

		var raw struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(message, &raw); err != nil {
			continue
		}

		event := MythicEvent{Type: raw.Type, Data: raw.Data}

		switch raw.Type {
		case "callback_checkin":
			var cb MythicCallback
			json.Unmarshal(raw.Data, &cb)
			event.Data = cb
		case "callback_checkout":
			var cb MythicCallback
			json.Unmarshal(raw.Data, &cb)
			event.Data = cb
		case "task_submit":
			var task MythicTask
			json.Unmarshal(raw.Data, &task)
			event.Data = task
		case "task_complete":
			var task MythicTask
			json.Unmarshal(raw.Data, &task)
			event.Data = task
		case "custom_event":
			var custom map[string]interface{}
			json.Unmarshal(raw.Data, &custom)
			event.Data = custom
		}

		if c.eventHandler != nil {
			c.eventHandler(event)
		}
	}
}

func (c *MythicWSClient) Stop() {
	close(c.stopCh)
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
	}
	c.mu.Unlock()
}

func (e *MythicEngine) SendWebSocketMessage(msgType string, data interface{}) error {
	msg := map[string]interface{}{
		"type": msgType,
		"data": data,
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal ws message: %w", err)
	}

	_ = payload
	return nil
}
