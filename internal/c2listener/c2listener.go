package c2listener

import (
	"context"
	"time"
)

type ListenerConfig struct {
	HTTPPort   int
	HTTPSPort  int
	DNSPort    int
	WSPort     int
	SessionTTL time.Duration
	CertFile   string
	KeyFile    string
}

type Listener struct{}

func NewListener(cfg ListenerConfig) *Listener {
	return &Listener{}
}

func (l *Listener) Start(ctx context.Context) error {
	return nil
}

func (l *Listener) Stop(ctx context.Context) {}
