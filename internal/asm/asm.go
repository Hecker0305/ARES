package asm

import (
	"github.com/ares/engine/internal/uuid"
	"sync"
	"time"
)

type AssetType string

const (
	AssetDomain    AssetType = "domain"
	AssetSubdomain AssetType = "subdomain"
	AssetIP        AssetType = "ip"
	AssetCert      AssetType = "certificate"
	AssetCloud     AssetType = "cloud"
	AssetService   AssetType = "service"
)

type ExposureLevel string

const (
	ExposureCritical ExposureLevel = "critical"
	ExposureHigh     ExposureLevel = "high"
	ExposureMedium   ExposureLevel = "medium"
	ExposureLow      ExposureLevel = "low"
	ExposureUnknown  ExposureLevel = "unknown"
)

type ASMAsset struct {
	ID            string        `json:"id"`
	Type          AssetType     `json:"type"`
	Name          string        `json:"name"`
	DiscoveredAt  time.Time     `json:"discovered_at"`
	LastSeenAt    time.Time     `json:"last_seen_at"`
	Exposure      ExposureLevel `json:"exposure"`
	Services      []string      `json:"services,omitempty"`
	CloudProvider string        `json:"cloud_provider,omitempty"`
	Region        string        `json:"region,omitempty"`
	Tags          []string      `json:"tags,omitempty"`
}

type ASMEngine struct {
	mu     sync.RWMutex
	assets map[string]*ASMAsset
}

func NewASM() *ASMEngine {
	return &ASMEngine{
		assets: make(map[string]*ASMAsset),
	}
}

func (a *ASMEngine) AddAsset(asset ASMAsset) string {
	a.mu.Lock()
	defer a.mu.Unlock()

	if asset.ID == "" {
		asset.ID = uuid.New()
	}
	asset.DiscoveredAt = time.Now()
	asset.LastSeenAt = time.Now()
	a.assets[asset.ID] = &asset
	return asset.ID
}

func (a *ASMEngine) UpdateAsset(id string, updates map[string]interface{}) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	asset, ok := a.assets[id]
	if !ok {
		return false
	}

	if v, ok := updates["name"]; ok {
		asset.Name = v.(string)
	}
	if v, ok := updates["exposure"]; ok {
		asset.Exposure = ExposureLevel(v.(string))
	}
	if v, ok := updates["cloud_provider"]; ok {
		asset.CloudProvider = v.(string)
	}
	asset.LastSeenAt = time.Now()
	return true
}

func (a *ASMEngine) GetAsset(id string) *ASMAsset {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.assets[id]
}

func (a *ASMEngine) ListAssets() []*ASMAsset {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]*ASMAsset, 0, len(a.assets))
	for _, asset := range a.assets {
		result = append(result, asset)
	}
	return result
}

func (a *ASMEngine) GetAssetsByType(t AssetType) []*ASMAsset {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var result []*ASMAsset
	for _, asset := range a.assets {
		if asset.Type == t {
			result = append(result, asset)
		}
	}
	return result
}

func (a *ASMEngine) GetStats() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	typeCount := make(map[AssetType]int)
	exposureCount := make(map[ExposureLevel]int)

	for _, asset := range a.assets {
		typeCount[asset.Type]++
		exposureCount[asset.Exposure]++
	}

	return map[string]interface{}{
		"total_assets":    len(a.assets),
		"by_type":         typeCount,
		"by_exposure":     exposureCount,
		"last_discovered": time.Now(),
	}
}
