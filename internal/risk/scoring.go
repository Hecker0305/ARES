package risk

import (
	"math"
	"sync"
	"time"
)

type AssetCriticality string

const (
	CriticalityCritical AssetCriticality = "critical"
	CriticalityHigh     AssetCriticality = "high"
	CriticalityMedium   AssetCriticality = "medium"
	CriticalityLow      AssetCriticality = "low"
)

type Asset struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Type          string           `json:"type"`
	Criticality   AssetCriticality `json:"criticality"`
	BusinessValue float64          `json:"business_value"`
	Owner         string           `json:"owner"`
	Compliance    []string         `json:"compliance,omitempty"`
}

type BusinessImpact struct {
	AssetID         string    `json:"asset_id"`
	ImpactScore     float64   `json:"impact_score"`
	FinancialImpact float64   `json:"financial_impact"`
	Reputational    float64   `json:"reputational"`
	Regulatory      float64   `json:"regulatory"`
	Operational     float64   `json:"operational"`
	CalculatedAt    time.Time `json:"calculated_at"`
}

type RiskTrend struct {
	Date      time.Time `json:"date"`
	AvgScore  float64   `json:"avg_score"`
	MaxScore  float64   `json:"max_score"`
	TotalOpen int       `json:"total_open"`
}

type SLATracker struct {
	mu       sync.RWMutex
	policies map[string]SLAPolicy
	entries  []SLAEntry
}

type SLAPolicy struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	Severity       string        `json:"severity"`
	MaxRemediation time.Duration `json:"max_remediation"`
}

type SLAEntry struct {
	ID           string     `json:"id"`
	FindingID    string     `json:"finding_id"`
	PolicyID     string     `json:"policy_id"`
	DetectedAt   time.Time  `json:"detected_at"`
	RemediatedAt *time.Time `json:"remediated_at,omitempty"`
	DueBy        time.Time  `json:"due_by"`
	Overdue      bool       `json:"overdue"`
}

type RiskEngine struct {
	mu      sync.RWMutex
	assets  map[string]Asset
	impacts map[string]BusinessImpact
	trends  []RiskTrend
	sla     *SLATracker
}

func New() *RiskEngine {
	return &RiskEngine{
		assets:  make(map[string]Asset),
		impacts: make(map[string]BusinessImpact),
		sla: &SLATracker{
			policies: map[string]SLAPolicy{
				"sla-critical": {ID: "sla-critical", Name: "Critical Finding SLA", Severity: "critical", MaxRemediation: 24 * time.Hour},
				"sla-high":     {ID: "sla-high", Name: "High Finding SLA", Severity: "high", MaxRemediation: 7 * 24 * time.Hour},
				"sla-medium":   {ID: "sla-medium", Name: "Medium Finding SLA", Severity: "medium", MaxRemediation: 30 * 24 * time.Hour},
				"sla-low":      {ID: "sla-low", Name: "Low Finding SLA", Severity: "low", MaxRemediation: 90 * 24 * time.Hour},
			},
		},
	}
}

func (r *RiskEngine) RegisterAsset(a Asset) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.assets[a.ID] = a
}

func (r *RiskEngine) GetAsset(id string) (Asset, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.assets[id]
	return a, ok
}

func (r *RiskEngine) ListAssets() []Asset {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []Asset
	for _, a := range r.assets {
		result = append(result, a)
	}
	return result
}

func (r *RiskEngine) CalculateBusinessImpact(assetID string, vulnerabilityScore float64, exploitability float64) BusinessImpact {
	asset, ok := r.GetAsset(assetID)
	if !ok {
		return BusinessImpact{}
	}

	criticalityWeight := map[AssetCriticality]float64{
		CriticalityCritical: 1.0,
		CriticalityHigh:     0.75,
		CriticalityMedium:   0.5,
		CriticalityLow:      0.25,
	}

	cw := criticalityWeight[asset.Criticality]
	baseImpact := vulnerabilityScore * 10.0 * cw * exploitability

	impact := BusinessImpact{
		AssetID:         assetID,
		ImpactScore:     math.Min(baseImpact, 10.0),
		FinancialImpact: baseImpact * 0.4,
		Reputational:    baseImpact * 0.3,
		Regulatory:      baseImpact * 0.2,
		Operational:     baseImpact * 0.1,
		CalculatedAt:    time.Now(),
	}

	r.mu.Lock()
	r.impacts[assetID] = impact
	r.mu.Unlock()

	return impact
}

func (r *RiskEngine) GetImpact(assetID string) (BusinessImpact, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	impact, ok := r.impacts[assetID]
	return impact, ok
}

func (r *RiskEngine) RecordTrend(avgScore, maxScore float64, totalOpen int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trends = append(r.trends, RiskTrend{
		Date:      time.Now(),
		AvgScore:  avgScore,
		MaxScore:  maxScore,
		TotalOpen: totalOpen,
	})
	if len(r.trends) > 365 {
		r.trends = r.trends[len(r.trends)-365:]
	}
}

func (r *RiskEngine) GetTrends(days int) []RiskTrend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if days <= 0 || days > len(r.trends) {
		days = len(r.trends)
	}
	if days == 0 {
		return nil
	}
	result := make([]RiskTrend, days)
	copy(result, r.trends[len(r.trends)-days:])
	return result
}

func (r *RiskEngine) CurrentRiskProfile() map[string]float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var totalScore float64
	var count int
	var maxScore float64
	var criticalCount, highCount int

	for _, impact := range r.impacts {
		totalScore += impact.ImpactScore
		count++
		if impact.ImpactScore > maxScore {
			maxScore = impact.ImpactScore
		}
	}
	for _, asset := range r.assets {
		if asset.Criticality == CriticalityCritical {
			criticalCount++
		}
		if asset.Criticality == CriticalityHigh {
			highCount++
		}
	}

	return map[string]float64{
		"avg_impact_score":    safeDivide(totalScore, float64(count)),
		"max_impact_score":    maxScore,
		"total_assets_scored": float64(count),
		"critical_assets":     float64(criticalCount),
		"high_assets":         float64(highCount),
	}
}

func safeDivide(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func (s *SLATracker) GetPolicy(severity string) *SLAPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.policies {
		if p.Severity == severity {
			return &p
		}
	}
	return nil
}

func (s *SLATracker) StartSLA(findingID, severity string) SLAEntry {
	policy := s.GetPolicy(severity)
	if policy == nil {
		return SLAEntry{}
	}

	entry := SLAEntry{
		ID:         findingID,
		FindingID:  findingID,
		PolicyID:   policy.ID,
		DetectedAt: time.Now(),
		DueBy:      time.Now().Add(policy.MaxRemediation),
		Overdue:    false,
	}

	s.mu.Lock()
	s.entries = append(s.entries, entry)
	s.mu.Unlock()

	return entry
}

func (s *SLATracker) CompleteSLA(findingID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for i := range s.entries {
		if s.entries[i].FindingID == findingID && s.entries[i].RemediatedAt == nil {
			s.entries[i].RemediatedAt = &now
			s.entries[i].Overdue = now.After(s.entries[i].DueBy)
			break
		}
	}
}

func (s *SLATracker) GetSLAEntries(overdueOnly bool) []SLAEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []SLAEntry
	now := time.Now()
	for _, e := range s.entries {
		if e.RemediatedAt == nil && now.After(e.DueBy) {
			e.Overdue = true
		}
		if overdueOnly && !e.Overdue {
			continue
		}
		result = append(result, e)
	}
	return result
}

func (s *SLATracker) SLAComplianceRate() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total, met int
	for _, e := range s.entries {
		total++
		if e.RemediatedAt != nil && !e.Overdue {
			met++
		}
	}
	if total == 0 {
		return 100
	}
	return float64(met) / float64(total) * 100
}
