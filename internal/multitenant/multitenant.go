package multitenant

import "errors"

type Tenant struct {
	ID       string
	IsActive bool
	MaxScans int
}

type TenantManager struct{}

func (tm *TenantManager) Get(id string) (*Tenant, error) {
	return &Tenant{ID: id, IsActive: true, MaxScans: 10}, nil
}

type ScanCounter struct{}

func (sc *ScanCounter) CheckQuota(tenantID string, maxScans int) error {
	return nil
}

func (sc *ScanCounter) Increment(tenantID string) {}

var ErrQuotaExceeded = errors.New("scan quota exceeded")
