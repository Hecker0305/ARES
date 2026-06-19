package oob

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
	"github.com/ares/engine/internal/security"
)

const (
	defaultHTTPPort      = 18080
	defaultDNSPort       = 5353
	tokenLen             = 32
	callbackTTL          = 10 * time.Minute
	maxCallbacksPerToken = 100
	maxBodySize          = 1 << 20
	maxTimestampAge      = 5 * time.Minute
)

type Callback struct {
	Token      string
	Protocol   string
	SourceIP   string
	Payload    string
	ReceivedAt time.Time
}

type OOBServer struct {
	mu           sync.RWMutex
	callbacks    map[string][]Callback
	Domain       string
	httpPort     int
	dnsPort      int
	smtpPort     int
	httpSrv      *http.Server
	dnsConn      *net.UDPConn
	smtpListener net.Listener
	subscribers  map[string][]chan struct{}
	subMu        sync.Mutex
	authToken    string
	hmacSecret   []byte
	rateLimitMu  sync.Mutex
	rateCounts   map[string]int
	rateReset    time.Time
	dnsRateMu    sync.Mutex
	dnsCounts    map[string]int
	dnsReset     time.Time
	dnsStopCh    chan struct{}
}

func NewOOBServer(httpPort, dnsPort int) *OOBServer {
	if httpPort == 0 {
		httpPort = defaultHTTPPort
	}
	if dnsPort == 0 {
		dnsPort = defaultDNSPort
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		logger.Error(fmt.Sprintf("[OOBServer] FATAL: failed to generate HMAC secret: %v", err))
		return nil
	}
	return &OOBServer{
		callbacks:   make(map[string][]Callback),
		subscribers: make(map[string][]chan struct{}),
		Domain:      fmt.Sprintf("oob.localhost:%d", httpPort),
		httpPort:    httpPort,
		dnsPort:     dnsPort,
		smtpPort:    2525,
		hmacSecret:  secret,
		rateCounts:  make(map[string]int),
		rateReset:   time.Now(),
		dnsCounts:   make(map[string]int),
		dnsReset:    time.Now(),
		dnsStopCh:   make(chan struct{}),
	}
}

func NewOOBServerWithAuth(httpPort, dnsPort int, authToken string) *OOBServer {
	s := NewOOBServer(httpPort, dnsPort)
	s.authToken = authToken
	return s
}

func (s *OOBServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHTTP)
	s.httpSrv = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.httpPort),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 3)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("http panic: %v", r)
			}
		}()
		logger.Info(fmt.Sprintf("[OOBServer] HTTP callback listener on :%d", s.httpPort))
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("[OOBServer] HTTP error: %v", err)
		}
	}()

	go func() {
		if err := s.runDNS(ctx); err != nil {
			errCh <- err
		}
	}()

	go func() {
		if err := s.runSMTP(ctx); err != nil {
			logger.Warn(fmt.Sprintf("[OOBServer] SMTP listener error: %v", err))
		}
	}()

	go s.purgeLoop(ctx)

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func (s *OOBServer) Stop(ctx context.Context) error {
	if s.httpSrv != nil {
		s.httpSrv.Shutdown(ctx)
	}
	if s.smtpListener != nil {
		s.smtpListener.Close()
	}
	if s.dnsConn != nil {
		s.dnsConn.Close()
	}
	close(s.dnsStopCh)
	return nil
}

func (s *OOBServer) runDNS(ctx context.Context) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: s.dnsPort})
	if err != nil {
		return fmt.Errorf("dns listener failed on :%d: %w", s.dnsPort, err)
	}
	s.dnsConn = conn
	logger.Info(fmt.Sprintf("[OOBServer] DNS callback listener on UDP :%d", s.dnsPort))
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	const maxDNSWorkers = 10
	dnsTasks := make(chan dnsTask, 100)
	var wg sync.WaitGroup
	dnsCtx, dnsCancel := context.WithCancel(ctx)
	defer dnsCancel()
	for i := 0; i < maxDNSWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-dnsCtx.Done():
					return
				case task, ok := <-dnsTasks:
					if !ok {
						return
					}
					s.handleDNS(task.data, task.src)
				}
			}
		}()
	}

	rateLimiter := make(chan struct{}, 100)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.dnsStopCh:
				return
			case <-ticker.C:
			}
			for i := 0; i < 100; i++ {
				select {
				case rateLimiter <- struct{}{}:
				default:
					goto done
				}
			}
		done:
		}
	}()

	buf := make([]byte, 512)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				close(dnsTasks)
				wg.Wait()
				return nil
			}
			continue
		}

		select {
		case <-rateLimiter:
			data := make([]byte, n)
			copy(data, buf[:n])
			select {
			case dnsTasks <- dnsTask{data: data, src: src}:
			default:
				logger.Info(fmt.Sprintf("[OOBServer] DNS task queue full, dropping query from %s", src))
			}
		default:
			logger.Info(fmt.Sprintf("[OOBServer] DNS rate limit hit, dropping query from %s", src))
		}
	}
}

type dnsTask struct {
	data []byte
	src  *net.UDPAddr
}

func (s *OOBServer) handleDNS(data []byte, src *net.UDPAddr) {
	if len(data) < 12 || len(data) > 512 {
		return
	}

	clientIP := src.IP.String()

	s.dnsRateMu.Lock()
	if time.Since(s.dnsReset) > time.Minute {
		s.dnsCounts = make(map[string]int)
		s.dnsReset = time.Now()
	}
	s.dnsCounts[clientIP]++
	count := s.dnsCounts[clientIP]
	s.dnsRateMu.Unlock()

	if count > 10 {
		return
	}

	transactionID := binary.BigEndian.Uint16(data[0:2])

	qr := data[2] & 0x80
	if qr != 0 {
		return
	}

	qdcount := binary.BigEndian.Uint16(data[4:6])
	if qdcount == 0 || qdcount > 1 {
		return
	}

	qname := dnsName(data[12:])
	if qname == "" || len(qname) > 255 {
		return
	}

	token := strings.SplitN(qname, ".", 2)[0]
	if len(token) > 64 || token == "" {
		return
	}

	hasAlpha := false
	for _, c := range token {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			hasAlpha = true
			break
		}
	}
	if !hasAlpha {
		return
	}

	cb := Callback{
		Token:      token,
		Protocol:   "dns",
		SourceIP:   src.String(),
		Payload:    qname,
		ReceivedAt: time.Now(),
	}
	s.mu.Lock()
	if len(s.callbacks[token]) < maxCallbacksPerToken {
		s.callbacks[token] = append(s.callbacks[token], cb)
	}
	s.mu.Unlock()
	s.notifySubscribers(token)

	nonce := transactionID
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], nonce)
	resp[2], resp[3] = 0x81, 0x83
	resp[7] = 0
	resp[8] = 0
	resp[9] = 0
	if s.dnsConn != nil {
		s.dnsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		s.dnsConn.WriteToUDP(resp, src)
	}
}

func dnsName(data []byte) string {
	var parts []string
	i := 0
	visited := make(map[int]bool)
	for i < len(data) {
		if visited[i] {
			break
		}
		visited[i] = true
		l := int(data[i])
		if l == 0 {
			break
		}
		if l&0xC0 == 0xC0 {
			if i+1 >= len(data) {
				break
			}
			offset := (int(l&0x3F) << 8) | int(data[i+1])
			if offset >= len(data) {
				break
			}
			i = offset
			continue
		}
		i++
		if i+l > len(data) {
			break
		}
		parts = append(parts, string(data[i:i+l]))
		i += l
	}
	return strings.Join(parts, ".")
}

func (s *OOBServer) purgeLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cutoff := time.Now().Add(-callbackTTL)
			s.mu.Lock()
			for token, cbs := range s.callbacks {
				var live []Callback
				for _, cb := range cbs {
					if cb.ReceivedAt.After(cutoff) {
						live = append(live, cb)
					}
				}
				if len(live) == 0 && len(cbs) > 0 {
					delete(s.callbacks, token)
				} else {
					s.callbacks[token] = live
				}
			}
			s.mu.Unlock()

			s.subMu.Lock()
			for token, subs := range s.subscribers {
				var active []chan struct{}
				for _, ch := range subs {
					select {
					case ch <- struct{}{}:
						active = append(active, ch)
					default:
					}
				}
				if len(active) == 0 {
					delete(s.subscribers, token)
				} else {
					s.subscribers[token] = active
				}
			}
			s.subMu.Unlock()

			s.rateLimitMu.Lock()
			if time.Now().After(s.rateReset) {
				s.rateCounts = make(map[string]int)
				s.rateReset = time.Now().Add(time.Minute)
			}
			s.rateLimitMu.Unlock()

			s.dnsRateMu.Lock()
			if time.Now().After(s.dnsReset) {
				s.dnsCounts = make(map[string]int)
				s.dnsReset = time.Now().Add(time.Minute)
			}
			s.dnsRateMu.Unlock()
		}
	}
}

func (s *OOBServer) HTTPPayload(token string) string {
	return fmt.Sprintf("http://%s/%s", s.Domain, token)
}

func (s *OOBServer) DNSPayload(token string) string {
	return fmt.Sprintf("%s.%s", token, s.Domain)
}

func (s *OOBServer) NewToken() string {
	b := make([]byte, tokenLen)
	if _, err := rand.Read(b); err != nil {
		logger.Error(fmt.Sprintf("[OOBServer] CRITICAL: crypto/rand failed: %v", err))
		mac := hmac.New(sha256.New, s.hmacSecret)
		mac.Write([]byte(uuid.New()))
		b = mac.Sum(nil)[:tokenLen]
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.callbacks[token] = nil
	s.mu.Unlock()
	return token
}

func (s *OOBServer) NewSignedToken(scanID string) string {
	b := make([]byte, tokenLen)
	if _, err := rand.Read(b); err != nil {
		mac := hmac.New(sha256.New, s.hmacSecret)
		mac.Write([]byte(uuid.New()))
		b = mac.Sum(nil)[:tokenLen]
	}
	token := hex.EncodeToString(b)

	ts := time.Now().Unix()
	mac := hmac.New(sha256.New, s.hmacSecret)
	mac.Write([]byte(scanID))
	mac.Write([]byte{0})
	mac.Write([]byte(token))
	mac.Write([]byte{0})
	mac.Write([]byte(fmt.Sprintf("%d", ts)))
	sig := hex.EncodeToString(mac.Sum(nil))

	signed := token + "." + sig + "." + strconv.FormatInt(ts, 10)
	s.mu.Lock()
	s.callbacks[signed] = nil
	s.mu.Unlock()
	return signed
}

func (s *OOBServer) VerifySignedToken(scanID, signedToken string) bool {
	parts := strings.SplitN(signedToken, ".", 3)
	if len(parts) < 2 {
		return false
	}
	token := parts[0]
	sig := parts[1]

	mac := hmac.New(sha256.New, s.hmacSecret)
	mac.Write([]byte(scanID))
	mac.Write([]byte{0})
	mac.Write([]byte(token))

	if len(parts) == 3 {
		tsStr := parts[2]
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			return false
		}
		callbackTime := time.Unix(ts, 0)
		if time.Since(callbackTime) > maxTimestampAge {
			return false
		}
		mac.Write([]byte{0})
		mac.Write([]byte(tsStr))
	}

	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expected))
}

func (s *OOBServer) HasCallback(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.callbacks[token]) > 0
}

func (s *OOBServer) WaitForCallback(ctx context.Context, token string, timeout time.Duration) (bool, []Callback) {
	s.mu.RLock()
	if cbs := s.callbacks[token]; len(cbs) > 0 {
		s.mu.RUnlock()
		return true, cbs
	}
	s.mu.RUnlock()

	ch := make(chan struct{}, 1)
	s.subMu.Lock()
	s.subscribers[token] = append(s.subscribers[token], ch)
	s.subMu.Unlock()

	defer func() {
		s.subMu.Lock()
		subs := s.subscribers[token]
		for i, sub := range subs {
			if sub == ch {
				s.subscribers[token] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		if len(s.subscribers[token]) == 0 {
			delete(s.subscribers, token)
		}
		s.subMu.Unlock()
	}()

	select {
	case <-ch:
	case <-ctx.Done():
		return false, nil
	case <-time.After(timeout):
		s.mu.RLock()
		cbs := s.callbacks[token]
		s.mu.RUnlock()
		return len(cbs) > 0, cbs
	}

	s.mu.RLock()
	cbs := s.callbacks[token]
	s.mu.RUnlock()
	return len(cbs) > 0, cbs
}

func (s *OOBServer) notifySubscribers(token string) {
	s.subMu.Lock()
	subs := s.subscribers[token]
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	s.subMu.Unlock()
}

func (s *OOBServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	s.rateLimitMu.Lock()
	now := time.Now()
	if now.Sub(s.rateReset) > time.Second {
		s.rateCounts = make(map[string]int)
		s.rateReset = now
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	clientIP := host
	s.rateCounts[clientIP]++
	if s.rateCounts[clientIP] > 100 {
		s.rateLimitMu.Unlock()
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	s.rateLimitMu.Unlock()

	if s.authToken != "" {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || !security.SecureCompare(strings.TrimPrefix(auth, "Bearer "), s.authToken) {
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}
	}

	hmacSig := r.Header.Get("X-OOB-Signature")
	hmacTimestamp := r.Header.Get("X-OOB-Timestamp")
	if hmacSig != "" {
		if !s.validateHMACSignature(hmacSig, hmacTimestamp, r) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	path := strings.TrimPrefix(r.URL.Path, "/")
	token := strings.SplitN(path, "/", 2)[0]
	if token == "" || len(token) < 4 || len(token) > 128 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if strings.Contains(token, ".") {
		parts := strings.SplitN(token, ".", 3)
		baseToken := parts[0]
		sig := parts[1]
		var tsStr string
		if len(parts) == 3 {
			tsStr = parts[2]
		}

		mac := hmac.New(sha256.New, s.hmacSecret)
		mac.Write([]byte("callback"))
		mac.Write([]byte{0})
		mac.Write([]byte(baseToken))
		if tsStr != "" {
			mac.Write([]byte{0})
			mac.Write([]byte(tsStr))

			ts, err := strconv.ParseInt(tsStr, 10, 64)
			if err != nil {
				http.Error(w, "invalid timestamp", http.StatusUnauthorized)
				return
			}
			callbackTime := time.Unix(ts, 0)
			if time.Since(callbackTime) > maxTimestampAge {
				http.Error(w, "expired timestamp", http.StatusUnauthorized)
				return
			}
		}
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(sig), []byte(expected)) {
			http.Error(w, "invalid token signature", http.StatusUnauthorized)
			return
		}
		token = baseToken
	}

	cb := Callback{
		Token:      token,
		Protocol:   "http",
		SourceIP:   r.RemoteAddr,
		Payload:    r.URL.String(),
		ReceivedAt: time.Now(),
	}
	s.mu.Lock()
	if len(s.callbacks[token]) < maxCallbacksPerToken {
		s.callbacks[token] = append(s.callbacks[token], cb)
	}
	s.mu.Unlock()
	s.notifySubscribers(token)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

func (s *OOBServer) validateHMACSignature(sig, timestampStr string, r *http.Request) bool {
	if sig == "" {
		return false
	}

	if timestampStr != "" {
		ts, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			return false
		}
		tsTime := time.Unix(ts, 0)
		if time.Since(tsTime) > maxTimestampAge {
			return false
		}
	}

	mac := hmac.New(sha256.New, s.hmacSecret)
	mac.Write([]byte(r.Method))
	mac.Write([]byte(r.URL.Path))
	if timestampStr != "" {
		mac.Write([]byte(timestampStr))
	}
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expected))
}

func (s *OOBServer) URLFor(scanID string) string {
	signed := s.NewSignedToken(scanID)
	payload := s.HTTPPayload(signed)
	return payload
}

func (s *OOBServer) runSMTP(ctx context.Context) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.smtpPort))
	if err != nil {
		return fmt.Errorf("[OOBServer] SMTP listen error: %v", err)
	}
	s.smtpListener = listener
	logger.Info(fmt.Sprintf("[OOBServer] SMTP callback listener on :%d", s.smtpPort))

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	const maxSMTPWorkers = 10
	smtpTasks := make(chan net.Conn, 50)
	var wg sync.WaitGroup
	smtpCtx, smtpCancel := context.WithCancel(ctx)
	defer smtpCancel()
	for i := 0; i < maxSMTPWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-smtpCtx.Done():
					return
				case conn, ok := <-smtpTasks:
					if !ok {
						return
					}
					s.handleSMTP(conn)
				}
			}
		}()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			close(smtpTasks)
			wg.Wait()
			return nil
		}
		select {
		case smtpTasks <- conn:
		default:
			logger.Info(fmt.Sprintf("[OOBServer] SMTP task queue full, dropping connection from %s", conn.RemoteAddr()))
			conn.Close()
		}
	}
}

func (s *OOBServer) handleSMTP(conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	clientIP := conn.RemoteAddr().String()

	s.rateLimitMu.Lock()
	now := time.Now()
	if now.Sub(s.rateReset) > time.Second {
		s.rateCounts = make(map[string]int)
		s.rateReset = now
	}
	s.rateCounts[clientIP]++
	if s.rateCounts[clientIP] > 100 {
		s.rateLimitMu.Unlock()
		logger.Info(fmt.Sprintf("[OOBServer] SMTP rate limit hit, dropping from %s", clientIP))
		return
	}
	s.rateLimitMu.Unlock()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	data := string(buf[:n])
	token := extractTokenFromSMTP(data)
	if token == "" {
		return
	}

	cb := Callback{
		Token:      token,
		Protocol:   "smtp",
		SourceIP:   clientIP,
		Payload:    data,
		ReceivedAt: time.Now(),
	}
	s.mu.Lock()
	if len(s.callbacks[token]) < maxCallbacksPerToken {
		s.callbacks[token] = append(s.callbacks[token], cb)
	}
	s.mu.Unlock()
	s.notifySubscribers(token)
	logger.Info(fmt.Sprintf("[OOBServer] SMTP callback received for token: %s", token))
}

func extractTokenFromSMTP(data string) string {
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "rcpt to:") {
			parts := strings.Split(line, "@")
			if len(parts) > 1 {
				tokenPart := strings.Split(parts[0], ":")
				if len(tokenPart) > 1 {
					return strings.TrimSpace(tokenPart[1])
				}
			}
		}
		if strings.Contains(line, "X-Ares-Token:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
