package pivot

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/uuid"
)

type PivotConfig struct {
	SOCKS5Host string
	SOCKS5Port int
	SliverHost string
	SliverPort int
	CACert     string
	MTU        int
	LocalPort  int
	User       string
	Password   string
}

type PivotRoute struct {
	ID         string
	TargetHost string
	ViaSOCKS5  bool
	SOCKS5Addr string
	CreatedAt  time.Time
}

type PivotRouter struct {
	mu       sync.RWMutex
	routes   map[string]*PivotRoute
	active   bool
	config   PivotConfig
	listener net.Listener
	nextPort int
}

var (
	pivotListeners = make(map[string]net.Listener)
	pivotMu        sync.Mutex
)

func NewPivotRouter(cfg PivotConfig) (*PivotRouter, error) {
	if cfg.LocalPort == 0 {
		cfg.LocalPort = 10800
	}

	if cfg.User == "" || cfg.Password == "" {
		credUser := os.Getenv("ARES_PIVOT_USER")
		credPass := os.Getenv("ARES_PIVOT_PASS")
		if credUser == "" || credPass == "" {
			return nil, fmt.Errorf("SOCKS5 credentials required: set PivotConfig.User/Password or ARES_PIVOT_USER/ARES_PIVOT_PASS environment variables")
		}
		cfg.User = credUser
		cfg.Password = credPass
		os.Unsetenv("ARES_PIVOT_USER")
		os.Unsetenv("ARES_PIVOT_PASS")
	}

	return &PivotRouter{
		routes:   make(map[string]*PivotRoute),
		active:   false,
		config:   cfg,
		nextPort: 10800,
	}, nil
}

func (r *PivotRouter) AddRoute(target string) (*PivotRoute, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	route := &PivotRoute{
		ID:         uuid.New(),
		TargetHost: target,
		ViaSOCKS5:  true,
		SOCKS5Addr: fmt.Sprintf("127.0.0.1:%d", r.nextPort),
		CreatedAt:  time.Now(),
	}

	r.nextPort++
	if r.nextPort > 10900 {
		r.nextPort = 10800
	}

	r.routes[route.ID] = route
	return route, nil
}

func (r *PivotRouter) RemoveRoute(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.routes[id]; ok {
		delete(r.routes, id)
		return nil
	}
	return fmt.Errorf("route not found: %s", id)
}

func (r *PivotRouter) RouteFor(target string) *PivotRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, route := range r.routes {
		if route.TargetHost == target {
			return route
		}
	}
	return nil
}

func (r *PivotRouter) StartSOCKS5Listener(port int) error {
	r.mu.Lock()
	if r.active {
		r.mu.Unlock()
		return fmt.Errorf("SOCKS5 listener already active")
	}
	r.mu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen: %w", err)
	}

	pivotMu.Lock()
	pivotListeners[addr] = ln
	pivotMu.Unlock()

	r.mu.Lock()
	r.listener = ln
	r.active = true
	r.mu.Unlock()

	go r.serveSOCKS5(ln)
	return nil
}

func (r *PivotRouter) serveSOCKS5(ln net.Listener) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func(c net.Conn) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error(fmt.Sprintf("[Pivot] SOCKS5 handler panic: %v", rec))
				}
			}()
			r.handleSOCKS5(c)
		}(conn)
	}
}

func (r *PivotRouter) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	if nmethods > 0 {
		methods := make([]byte, nmethods)
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		authSupported := false
		for _, m := range methods {
			if m == 0x02 {
				authSupported = true
				break
			}
		}
		if !authSupported {
			conn.Write([]byte{0x05, 0xFF})
			return
		}
		conn.Write([]byte{0x05, 0x02})
		if !r.authenticateSOCKS5(conn) {
			return
		}
	} else {
		conn.Write([]byte{0x05, 0xFF})
		return
	}

	reqBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqBuf); err != nil {
		return
	}
	if reqBuf[0] != 0x05 || reqBuf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01})
		return
	}

	var targetHost string
	switch reqBuf[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		targetHost = net.IP(ip).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := conn.Read(lenBuf); err != nil {
			return
		}
		hostBuf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, hostBuf); err != nil {
			return
		}
		targetHost = string(hostBuf)
	}

	portBuf := make([]byte, 2)
	if _, err := conn.Read(portBuf); err != nil {
		return
	}
	targetPort := int(portBuf[0])<<8 | int(portBuf[1])
	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)

	if targetPort < 1 || targetPort > 65535 {
		conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	targetIP := net.ParseIP(targetHost)
	if targetIP != nil {
		if targetIP.IsLoopback() || targetIP.IsPrivate() || targetIP.IsLinkLocalUnicast() || targetIP.IsUnspecified() {
			conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return
		}
	}
	if strings.HasSuffix(targetHost, ".local") || strings.HasSuffix(targetHost, ".internal") {
		conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	r.mu.RLock()
	route := r.RouteFor(targetHost)
	r.mu.RUnlock()

	var dialAddr string
	if route != nil {
		dialAddr = route.SOCKS5Addr
	} else if r.config.SliverHost != "" {
		dialAddr = fmt.Sprintf("%s:%d", r.config.SliverHost, r.config.SliverPort)
	} else {
		dialAddr = targetAddr
	}

	var target net.Conn
	var err error

	if route != nil && strings.HasPrefix(route.SOCKS5Addr, "127.0.0.1") {
		parts := strings.Split(route.SOCKS5Addr, ":")
		if len(parts) == 2 {
			sliverAddr := fmt.Sprintf("%s:%d", r.config.SliverHost, r.config.SliverPort)
			target, err = r.dialSliver(sliverAddr, targetAddr)
		}
	} else {
		target, err = net.DialTimeout("tcp", dialAddr, 10*time.Second)
	}

	if err != nil {
		conn.Write([]byte{0x05, 0x03, 0x00, 0x01})
		return
	}
	defer target.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	go func() {
		defer cancel()
		r.copyWithContext(conn, target, ctx)
	}()
	go func() {
		defer cancel()
		r.copyWithContext(target, conn, ctx)
	}()
}

func (r *PivotRouter) dialSliver(sliverAddr, target string) (net.Conn, error) {
	if r.config.CACert != "" {
		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(r.config.CACert)
		if err == nil {
			certPool.AppendCertsFromPEM(caCert)
		}
		cfg := &tls.Config{
			RootCAs:            certPool,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		}
		conn, err := tls.Dial("tcp", sliverAddr, cfg)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	return net.DialTimeout("tcp", sliverAddr, 10*time.Second)
}

func (r *PivotRouter) copyWithContext(dst, src net.Conn, ctx context.Context) {
	buf := make([]byte, r.config.MTU)
	if r.config.MTU == 0 {
		buf = make([]byte, 8192)
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if tcpConn, ok := src.(*net.TCPConn); ok {
			tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (r *PivotRouter) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.listener != nil {
		r.listener.Close()
	}

	r.active = false
	r.routes = make(map[string]*PivotRoute)

	pivotMu.Lock()
	for addr, ln := range pivotListeners {
		ln.Close()
		delete(pivotListeners, addr)
	}
	pivotMu.Unlock()

	return nil
}

func (r *PivotRouter) Active() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

func (r *PivotRouter) socks5Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", r.allocPort())
}

func (r *PivotRouter) allocPort() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	port := r.nextPort
	r.nextPort++
	if r.nextPort > 10900 {
		r.nextPort = 10800
	}
	return port
}

func ViaPivot(cmd string, route *PivotRoute) string {
	if route == nil {
		return cmd
	}
	socks5Addr := route.SOCKS5Addr
	if !strings.HasPrefix(socks5Addr, "socks5://") {
		socks5Addr = "socks5://" + socks5Addr
	}
	return fmt.Sprintf("ALL_PROXY=%s %s", socks5Addr, cmd)
}

func (r *PivotRouter) authenticateSOCKS5(conn net.Conn) bool {
	authBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, authBuf); err != nil {
		return false
	}
	if authBuf[0] != 0x01 {
		conn.Write([]byte{0x01, 0xFF})
		return false
	}
	ulen := int(authBuf[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return false
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return false
	}
	plen := int(plenBuf[0])
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return false
	}
	expectedUser := r.config.User
	expectedPass := r.config.Password

	if expectedUser == "" || expectedPass == "" {
		logger.Warn("[Pivot] SOCKS5 proxy disabled: credentials not set in config or environment")
		conn.Write([]byte{0x01, 0xFF})
		return false
	}

	if subtle.ConstantTimeCompare(uname, []byte(expectedUser)) != 1 ||
		subtle.ConstantTimeCompare(passwd, []byte(expectedPass)) != 1 {
		conn.Write([]byte{0x01, 0xFF})
		return false
	}
	conn.Write([]byte{0x01, 0x00})
	return true
}
