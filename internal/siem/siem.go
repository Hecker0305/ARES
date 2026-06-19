package siem

import "context"

type SIEMConfig struct {
	Type     string
	Endpoint string
	APIKey   string
	Batch    bool
}

type SIEMClient struct{}

func NewSIEMClient(cfg SIEMConfig) *SIEMClient {
	return &SIEMClient{}
}

type SIEMEvent struct {
	EventType  string
	Severity   string
	Target     string
	VulnType   string
	Payload    string
	Evidence   string
	Confidence float64
	ScanID     string
	Metadata   map[string]string
}

func (c *SIEMClient) Push(ctx context.Context, event SIEMEvent) error {
	return nil
}
