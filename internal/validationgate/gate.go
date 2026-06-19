package validationgate

import (
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/ares/engine/internal/logger"
)

const PassThreshold = 0.7

type QuestionCategory int

const (
	CategoryReproducibility QuestionCategory = iota
	CategoryImpact          QuestionCategory = iota
	CategoryScope           QuestionCategory = iota
	CategoryAuth            QuestionCategory = iota
	CategoryData            QuestionCategory = iota
	CategoryChaining        QuestionCategory = iota
	CategoryPoC             QuestionCategory = iota
)

func (c QuestionCategory) String() string {
	switch c {
	case CategoryReproducibility:
		return "Reproducibility"
	case CategoryImpact:
		return "Impact"
	case CategoryScope:
		return "Scope"
	case CategoryAuth:
		return "Authentication"
	case CategoryData:
		return "Data Leakage"
	case CategoryChaining:
		return "Chaining"
	case CategoryPoC:
		return "Proof of Concept"
	default:
		return "Unknown"
	}
}

type Question struct {
	ID       string           `json:"id"`
	Text     string           `json:"text"`
	Weight   float64          `json:"weight"`
	Category QuestionCategory `json:"category"`
}

var DefaultQuestions = []Question{
	{
		ID:       "Q1",
		Text:     "Can attacker reproduce this?",
		Weight:   0.20,
		Category: CategoryReproducibility,
	},
	{
		ID:       "Q2",
		Text:     "Is there a real security impact?",
		Weight:   0.20,
		Category: CategoryImpact,
	},
	{
		ID:       "Q3",
		Text:     "Is this in scope?",
		Weight:   0.15,
		Category: CategoryScope,
	},
	{
		ID:       "Q4",
		Text:     "Is it exploitable without auth?",
		Weight:   0.10,
		Category: CategoryAuth,
	},
	{
		ID:       "Q5",
		Text:     "Does it leak sensitive data?",
		Weight:   0.15,
		Category: CategoryData,
	},
	{
		ID:       "Q6",
		Text:     "Can it be chained with other findings?",
		Weight:   0.10,
		Category: CategoryChaining,
	},
	{
		ID:       "Q7",
		Text:     "Is there a working PoC?",
		Weight:   0.10,
		Category: CategoryPoC,
	},
}

type Answer struct {
	QuestionID string `json:"question_id"`
	Passed     bool   `json:"passed"`
	Notes      string `json:"notes,omitempty"`
}

type GateResult struct {
	OverallScore    float64  `json:"overall_score"`
	Passed          bool     `json:"passed"`
	Answers         []Answer `json:"answers"`
	Recommendations []string `json:"recommendations,omitempty"`
	Kill            bool     `json:"kill"`
}

type Gate struct {
	mu        sync.RWMutex
	questions []Question
}

func New() *Gate {
	questions := make([]Question, len(DefaultQuestions))
	copy(questions, DefaultQuestions)
	return &Gate{
		questions: questions,
	}
}

func (g *Gate) Questions() []Question {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]Question, len(g.questions))
	copy(result, g.questions)
	return result
}

func (g *Gate) Validate(answers []Answer) GateResult {
	g.mu.RLock()
	defer g.mu.RUnlock()

	totalWeight := 0.0
	weightedScore := 0.0
	answerMap := make(map[string]Answer)
	resultAnswers := make([]Answer, 0)

	for _, a := range answers {
		answerMap[a.QuestionID] = a
	}

	for _, q := range g.questions {
		a, answered := answerMap[q.ID]
		if !answered {
			a = Answer{
				QuestionID: q.ID,
				Passed:     false,
				Notes:      "No answer provided",
			}
		}

		resultAnswers = append(resultAnswers, a)
		totalWeight += q.Weight
		if a.Passed {
			weightedScore += q.Weight
		}
	}

	if totalWeight == 0 {
		return GateResult{
			OverallScore:    0,
			Passed:          false,
			Answers:         resultAnswers,
			Recommendations: []string{"No questions configured"},
			Kill:            true,
		}
	}

	finalScore := weightedScore / totalWeight
	finalScore = math.Round(finalScore*100) / 100

	passed := finalScore >= PassThreshold

	recommendations := g.generateRecommendations(resultAnswers)

	kill := !passed

	result := GateResult{
		OverallScore:    finalScore,
		Passed:          passed,
		Answers:         resultAnswers,
		Recommendations: recommendations,
		Kill:            kill,
	}

	logger.Info("Validation gate result",
		logger.Fields{
			"score":  finalScore,
			"passed": passed,
			"killed": kill,
		})

	return result
}

func (g *Gate) generateRecommendations(answers []Answer) []string {
	recs := make([]string, 0)

	for _, a := range answers {
		if !a.Passed {
			switch a.QuestionID {
			case "Q1":
				recs = append(recs, "Provide clear reproduction steps with exact URLs, payloads, and expected vs actual behavior")
			case "Q2":
				recs = append(recs, "Describe the real-world security impact. What can an attacker actually achieve?")
			case "Q3":
				recs = append(recs, "Verify the target is in the program scope before reporting")
			case "Q4":
				recs = append(recs, "Test if the vulnerability is exploitable without authentication")
			case "Q5":
				recs = append(recs, "Document what sensitive data is leaked and how it violates the data classification policy")
			case "Q6":
				recs = append(recs, "Research if this can be combined with other findings for higher impact")
			case "Q7":
				recs = append(recs, "Develop a working proof of concept demonstrating the vulnerability")
			}
		}
	}

	return recs
}

func (g *Gate) FormatResult(result GateResult) string {
	var sb strings.Builder
	sb.WriteString("=== Validation Gate Results ===\n\n")

	for _, a := range result.Answers {
		status := "PASS"
		if !a.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s\n", status, a.QuestionID))
		if a.Notes != "" {
			sb.WriteString(fmt.Sprintf("     Note: %s\n", a.Notes))
		}
	}

	sb.WriteString(fmt.Sprintf("\nOverall Score: %.2f (threshold: %.2f)\n", result.OverallScore, PassThreshold))

	if result.Passed {
		sb.WriteString("RESULT: PASSED - Finding is valid\n")
	} else {
		sb.WriteString("RESULT: FAILED - Finding is KILLED\n")
	}

	if len(result.Recommendations) > 0 {
		sb.WriteString("\nRecommendations:\n")
		for _, r := range result.Recommendations {
			sb.WriteString(fmt.Sprintf("  - %s\n", r))
		}
	}

	if result.Kill {
		sb.WriteString("\n[KILLED] This finding does not meet the validation threshold and will not be reported.\n")
	}

	return sb.String()
}
