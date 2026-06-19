package engine

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/ares/engine/internal/agent"
)

type ScoringEngine struct {
	mu                  sync.RWMutex
	confidenceWeight    float64
	severityWeight      float64
	repeatabilityWeight float64
	evidenceWeight      float64
}

func NewScoringEngine() *ScoringEngine {
	return &ScoringEngine{
		confidenceWeight:    0.4,
		severityWeight:      0.3,
		repeatabilityWeight: 0.2,
		evidenceWeight:      0.1,
	}
}

func (s *ScoringEngine) CalculateScore(f agent.FindingData) float64 {
	confidenceScore := f.Confidence

	severityScore := s.severityToScore(f.Severity)

	repeatabilityScore := s.calculateRepeatability(f)

	evidenceScore := s.assessEvidenceQuality(f)

	s.mu.RLock()
	finalScore := confidenceScore*s.confidenceWeight +
		severityScore*s.severityWeight +
		repeatabilityScore*s.repeatabilityWeight +
		evidenceScore*s.evidenceWeight
	s.mu.RUnlock()

	return math.Min(1.0, math.Max(0.0, finalScore))
}

func (s *ScoringEngine) severityToScore(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 1.0
	case "high":
		return 0.8
	case "medium":
		return 0.5
	case "low":
		return 0.3
	case "info":
		return 0.1
	default:
		return 0.5
	}
}

func (s *ScoringEngine) calculateRepeatability(f agent.FindingData) float64 {
	if f.RawResponse == "" {
		return 0.5
	}

	if len(f.RawResponse) > 100 && len(f.RawResponse) < 10000 {
		return 0.8
	}

	return 0.4
}

func (s *ScoringEngine) assessEvidenceQuality(f agent.FindingData) float64 {
	score := 0.0

	if f.Error != "" {
		score -= 0.2
	} else {
		score += 0.3
	}

	if f.RawResponse != "" {
		score += 0.3

		hasEvidence := false
		evidenceKeywords := []string{"success", "found", "detected", "confirmed", "extracted"}
		lowerResp := strings.ToLower(f.RawResponse)
		for _, kw := range evidenceKeywords {
			if strings.Contains(lowerResp, kw) {
				hasEvidence = true
				break
			}
		}
		if hasEvidence {
			score += 0.2
		}
	}

	if f.Payload != "" {
		score += 0.2
	}

	return math.Min(1.0, math.Max(0.0, score))
}

func (s *ScoringEngine) AdaptiveThreshold() float64 {
	return 0.75
}

func (s *ScoringEngine) AdjustWeights(confidence, severity, repeatability, evidence float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.confidenceWeight = confidence
	s.severityWeight = severity
	s.repeatabilityWeight = repeatability
	s.evidenceWeight = evidence
}

func (s *ScoringEngine) CalculateCVSS(cveID string, cvss float64, epss float64, kev bool) float64 {
	baseScore := cvss / 10.0

	epssWeight := 0.1
	if epss > 0.5 {
		epssWeight = 0.2
	}

	kevWeight := 0.0
	if kev {
		kevWeight = 0.15
	}

	adjustedScore := baseScore*(1.0-epssWeight-kevWeight) + epss*epssWeight

	if kev {
		adjustedScore = math.Min(1.0, adjustedScore+0.1)
	}

	return math.Min(1.0, math.Max(0.0, adjustedScore))
}

func (s *ScoringEngine) RankFindings(findings []agent.FindingData) []agent.FindingData {
	scored := make([]struct {
		Finding agent.FindingData
		Score   float64
	}, len(findings))

	for i, f := range findings {
		scored[i] = struct {
			Finding agent.FindingData
			Score   float64
		}{Finding: f, Score: s.CalculateScore(f)}
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})

	result := make([]agent.FindingData, len(findings))
	for i, sc := range scored {
		result[i] = sc.Finding
	}

	return result
}

func (s *ScoringEngine) FinalScoreString(f agent.FindingData) string {
	score := s.CalculateScore(f)

	var rating string
	if score >= 0.9 {
		rating = "Critical"
	} else if score >= 0.7 {
		rating = "High"
	} else if score >= 0.5 {
		rating = "Medium"
	} else if score >= 0.3 {
		rating = "Low"
	} else {
		rating = "Info"
	}

	return fmt.Sprintf("Score: %.2f (%s)", score, rating)
}

func (s *ScoringEngine) GenerateCVSSVector(severity, vulnType string, confirmed bool) string {
	if !confirmed {
		return "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:N"
	}
	av, ac, pr, ui, sc, c, i, a := s.deriveCVSSMetrics(severity, vulnType)
	return fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s", av, ac, pr, ui, sc, c, i, a)
}

func (s *ScoringEngine) deriveCVSSMetrics(severity, vulnType string) (av, ac, pr, ui, scope, c, i, a string) {
	vt := strings.ToLower(vulnType)

	switch {
	case strings.Contains(vt, "rce") || strings.Contains(vt, "command_injection") || strings.Contains(vt, "os_command"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "N", "C", "H", "H", "H"
	case strings.Contains(vt, "sql") || strings.Contains(vt, "sqli"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "H", "H", "H"
	case strings.Contains(vt, "xss") || strings.Contains(vt, "cross_site"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "R", "C", "L", "L", "N"
	case strings.Contains(vt, "ssrf"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "H", "N", "N"
	case strings.Contains(vt, "lfi") || strings.Contains(vt, "rfi") || strings.Contains(vt, "path_traversal"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "H", "N", "N"
	case strings.Contains(vt, "idor") || strings.Contains(vt, "bola") || strings.Contains(vt, "bfla"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "H", "L", "N"
	case strings.Contains(vt, "xxe"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "H", "L", "N"
	case strings.Contains(vt, "ssti"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "C", "H", "H", "H"
	case strings.Contains(vt, "nosql"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "H", "L", "N"
	case strings.Contains(vt, "csrf"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "R", "U", "N", "L", "N"
	case strings.Contains(vt, "deserial") || strings.Contains(vt, "insecure_deserialization"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "H", "H", "H"
	case strings.Contains(vt, "smuggling") || strings.Contains(vt, "http_smuggling"):
		av, ac, pr, ui, scope, c, i, a = "N", "H", "N", "N", "U", "L", "L", "N"
	case strings.Contains(vt, "prototype_pollution"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "C", "L", "L", "L"
	case strings.Contains(vt, "graphql"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "L", "L", "N"
	case strings.Contains(vt, "cors"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "N", "U", "L", "N", "N"
	case strings.Contains(vt, "jwt") || strings.Contains(vt, "token"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "N", "U", "H", "H", "N"
	case strings.Contains(vt, "open_redirect"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "R", "U", "L", "N", "N"
	case strings.Contains(vt, "race") || strings.Contains(vt, "race_condition"):
		av, ac, pr, ui, scope, c, i, a = "N", "H", "L", "N", "U", "L", "L", "L"
	case strings.Contains(vt, "cloud") || strings.Contains(vt, "misconfig"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "H", "N", "U", "H", "H", "H"
	case strings.Contains(vt, "container") || strings.Contains(vt, "escape"):
		av, ac, pr, ui, scope, c, i, a = "L", "L", "L", "N", "C", "H", "H", "H"
	case strings.Contains(vt, "auth") || strings.Contains(vt, "bypass"):
		av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "N", "U", "H", "H", "N"
	default:
		sev := strings.ToLower(severity)
		switch sev {
		case "critical":
			av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "N", "C", "H", "H", "H"
		case "high":
			av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "H", "H", "H"
		case "medium":
			av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "R", "U", "L", "L", "N"
		case "low":
			av, ac, pr, ui, scope, c, i, a = "N", "H", "H", "R", "U", "L", "N", "N"
		default:
			av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "L", "L", "N"
		}
	}
	return
}

func (s *ScoringEngine) CVSSScoreFromVector(vector string) float64 {
	metrics := parseCVSSVector(vector)
	if len(metrics) == 0 {
		return 0.0
	}

	avScore := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acScore := map[string]float64{"L": 0.77, "H": 0.44}
	prScoreU := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prScoreC := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	uiScore := map[string]float64{"N": 0.85, "R": 0.62}
	ciaScore := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}

	iscBase := 1.0 - (1.0-ciaScore[metrics["C"]])*(1.0-ciaScore[metrics["I"]])*(1.0-ciaScore[metrics["A"]])

	scope := metrics["S"]
	var impact float64
	if scope == "C" {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15.0)
	} else {
		impact = 6.42 * iscBase
	}

	var pr float64
	if scope == "C" {
		pr = prScoreC[metrics["PR"]]
	} else {
		pr = prScoreU[metrics["PR"]]
	}

	exploitability := 8.22 * avScore[metrics["AV"]] * acScore[metrics["AC"]] * pr * uiScore[metrics["UI"]]

	var baseScore float64
	if impact <= 0 {
		baseScore = 0.0
	} else if scope == "C" {
		baseScore = math.Min(10.0, math.Round(1.08*(impact+exploitability)*10)/10)
	} else {
		baseScore = math.Min(10.0, math.Round((impact+exploitability)*10)/10)
	}

	return baseScore
}

var validCVSSMetrics = map[string][]string{
	"AV": {"N", "A", "L", "P"},
	"AC": {"L", "H"},
	"PR": {"N", "L", "H"},
	"UI": {"N", "R"},
	"S":  {"U", "C"},
	"C":  {"N", "L", "H"},
	"I":  {"N", "L", "H"},
	"A":  {"N", "L", "H"},
	"E":  {"X", "U", "P", "F", "H"},
	"RL": {"X", "O", "T", "W"},
	"RC": {"X", "U", "R", "C"},
}

func parseCVSSVector(vector string) map[string]string {
	metrics := make(map[string]string)
	parts := strings.Split(vector, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "CVSS:") {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			key := kv[0]
			val := kv[1]
			if validValues, ok := validCVSSMetrics[key]; ok {
				valid := false
				for _, vv := range validValues {
					if val == vv {
						valid = true
						break
					}
				}
				if !valid {
					continue
				}
			}
			metrics[key] = val
		}
	}
	return metrics
}
