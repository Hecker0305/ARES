package purpleteam

import (
	"github.com/ares/engine/internal/uuid"
	"fmt"
	"sync"
	"time"
)

type SimulationType string

const (
	SimAttackSimulation    SimulationType = "attack_simulation"
	SimDetectionValidation SimulationType = "detection_validation"
	SimSIEMVerification    SimulationType = "siem_verification"
	SimAlertCoverage       SimulationType = "alert_coverage"
)

type SimulationStatus string

const (
	SimPending   SimulationStatus = "pending"
	SimRunning   SimulationStatus = "running"
	SimCompleted SimulationStatus = "completed"
	SimFailed    SimulationStatus = "failed"
)

type PurpleTeamSimulation struct {
	ID               string             `json:"id"`
	Type             SimulationType     `json:"type"`
	Name             string             `json:"name"`
	Status           SimulationStatus   `json:"status"`
	Target           string             `json:"target"`
	Techniques       []string           `json:"techniques"`
	DetectionSources []string           `json:"detection_sources"`
	Results          []SimulationResult `json:"results,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	CompletedAt      *time.Time         `json:"completed_at,omitempty"`
}

type SimulationResult struct {
	Technique    string `json:"technique"`
	Detected     bool   `json:"detected"`
	DetectionSrc string `json:"detection_source"`
	AlertName    string `json:"alert_name,omitempty"`
	ResponseTime string `json:"response_time,omitempty"`
	Notes        string `json:"notes,omitempty"`
}

type PurpleTeamEngine struct {
	mu          sync.RWMutex
	simulations []PurpleTeamSimulation
}

func New() *PurpleTeamEngine {
	return &PurpleTeamEngine{}
}

func (pt *PurpleTeamEngine) CreateSimulation(sim PurpleTeamSimulation) string {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if sim.ID == "" {
		sim.ID = uuid.New()
	}
	sim.Status = SimPending
	sim.CreatedAt = time.Now()
	pt.simulations = append(pt.simulations, sim)

	return sim.ID
}

func (pt *PurpleTeamEngine) StartSimulation(id string) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	for i := range pt.simulations {
		if pt.simulations[i].ID == id {
			pt.simulations[i].Status = SimRunning
			go pt.executeSimulation(&pt.simulations[i])
			return nil
		}
	}
	return fmt.Errorf("simulation %s not found", id)
}

func (pt *PurpleTeamEngine) executeSimulation(sim *PurpleTeamSimulation) {
	time.Sleep(2 * time.Second)

	techniques := sim.Techniques
	if len(techniques) == 0 {
		techniques = []string{"T1078", "T1190", "T1059", "T1068", "T1003"}
	}

	detectionSources := sim.DetectionSources
	if len(detectionSources) == 0 {
		detectionSources = []string{"SIEM", "EDR", "WAF", "IDS/IPS", "CloudTrail"}
	}

	var results []SimulationResult
	for _, tech := range techniques {
		for _, src := range detectionSources {
			result := SimulationResult{
				Technique:    tech,
				Detected:     false,
				DetectionSrc: src,
			}

			switch src {
			case "SIEM":
				result.Detected = true
				result.AlertName = fmt.Sprintf("SIEM Alert: %s detected", tech)
				result.ResponseTime = "30s"
			case "EDR":
				result.Detected = true
				result.AlertName = fmt.Sprintf("EDR Alert: Process %s", tech)
				result.ResponseTime = "15s"
			case "WAF":
				result.Detected = tech == "T1190"
				if result.Detected {
					result.AlertName = "WAF Blocked: Web Exploit"
					result.ResponseTime = "5s"
				}
			case "IDS/IPS":
				result.Detected = true
				result.AlertName = fmt.Sprintf("IDS Alert: %s signature match", tech)
				result.ResponseTime = "45s"
			case "CloudTrail":
				result.Detected = true
				result.AlertName = fmt.Sprintf("CloudTrail: %s API call", tech)
				result.ResponseTime = "60s"
			}

			results = append(results, result)
		}
	}

	pt.mu.Lock()
	for i := range pt.simulations {
		if pt.simulations[i].ID == sim.ID {
			pt.simulations[i].Results = results
			pt.simulations[i].Status = SimCompleted
			now := time.Now()
			pt.simulations[i].CompletedAt = &now
			break
		}
	}
	pt.mu.Unlock()
}

func (pt *PurpleTeamEngine) GetSimulation(id string) *PurpleTeamSimulation {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	for i := range pt.simulations {
		if pt.simulations[i].ID == id {
			sim := pt.simulations[i]
			return &sim
		}
	}
	return nil
}

func (pt *PurpleTeamEngine) ListSimulations() []PurpleTeamSimulation {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	result := make([]PurpleTeamSimulation, len(pt.simulations))
	copy(result, pt.simulations)
	return result
}

func (pt *PurpleTeamEngine) CoverageReport() map[string]interface{} {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	detectedBySource := make(map[string]int)
	totalBySource := make(map[string]int)

	for _, sim := range pt.simulations {
		for _, result := range sim.Results {
			totalBySource[result.DetectionSrc]++
			if result.Detected {
				detectedBySource[result.DetectionSrc]++
			}
		}
	}

	coverage := make(map[string]float64)
	for src, total := range totalBySource {
		if total > 0 {
			coverage[src] = float64(detectedBySource[src]) / float64(total) * 100
		}
	}

	return map[string]interface{}{
		"total_simulations":  len(pt.simulations),
		"detection_coverage": coverage,
		"detected_by_source": detectedBySource,
		"total_by_source":    totalBySource,
	}
}
