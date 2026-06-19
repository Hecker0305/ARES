package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ares/engine/internal/logger"
	"github.com/ares/engine/internal/security"
)

type AgentMail interface {
	GenerateTempEmail() (string, error)
	GetInbox(email string, timeout time.Duration) (string, error)
}

type IDORResult struct {
	Confirmed    bool
	VictimData   string
	AttackerData string
	Severity     string
	Evidence     string
}

type IDORTwoAccount struct {
	mail AgentMail
}

func NewIDORTwoAccount(mail AgentMail) *IDORTwoAccount {
	return &IDORTwoAccount{mail: mail}
}

func (i *IDORTwoAccount) TwoAccountTest(ctx context.Context, targetURL, objectID, paramName string) (*IDORResult, error) {
	logger.Info("Starting two-account test for object", logger.Fields{"component": "IDOR", "object_id": objectID})

	// Validate target URL to prevent SSRF
	if err := security.ValidateURL(targetURL); err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	victimEmail, err := i.mail.GenerateTempEmail()
	if err != nil {
		return nil, fmt.Errorf("generate victim email: %w", err)
	}

	attackerEmail, err := i.mail.GenerateTempEmail()
	if err != nil {
		return nil, fmt.Errorf("generate attacker email: %w", err)
	}

	logger.Info("IDOR test participants", logger.Fields{"component": "IDOR", "victim_email": victimEmail, "attacker_email": attackerEmail})

	victimSession, err := i.registerAccount(ctx, targetURL, victimEmail, "VictimPass123!")
	if err != nil {
		return nil, fmt.Errorf("register victim: %w", err)
	}

	attackerSession, err := i.registerAccount(ctx, targetURL, attackerEmail, "AttackerPass123!")
	if err != nil {
		return nil, fmt.Errorf("register attacker: %w", err)
	}

	victimData, err := i.createObjectAsVictim(ctx, targetURL, victimSession, objectID)
	if err != nil {
		logger.Warn("Victim object creation warning", logger.Fields{"component": "IDOR", "error": err})
	}

	attackerData, err := i.accessObjectAsAttacker(ctx, targetURL, attackerSession, objectID, paramName)
	if err != nil {
		logger.Warn("Attacker object access warning", logger.Fields{"component": "IDOR", "error": err})
	}

	result := &IDORResult{
		VictimData:   victimData,
		AttackerData: attackerData,
		Severity:     "Medium",
		Evidence:     fmt.Sprintf("Victim accessed: %d bytes, Attacker accessed: %d bytes", len(victimData), len(attackerData)),
	}

	if victimData != "" && attackerData != "" {
		similarity := calculateSimilarity(victimData, attackerData)
		if similarity > 0.8 {
			result.Confirmed = true
			result.Severity = "High"
			result.Evidence += fmt.Sprintf("\nData identical (similarity: %.2f%%)", similarity*100)
		}
	}

	logger.Info("IDOR test complete", logger.Fields{"component": "IDOR", "confirmed": result.Confirmed, "severity": result.Severity})

	return result, nil
}

func (i *IDORTwoAccount) registerAccount(ctx context.Context, targetURL, email, password string) (string, error) {
	// Validate target URL to prevent SSRF
	if err := security.ValidateURL(targetURL); err != nil {
		return "", fmt.Errorf("invalid target URL: %w", err)
	}
	registerURL := targetURL + "/api/register"

	logger.Info("Attempting registration", logger.Fields{"component": "IDOR", "url": registerURL})

	regData, err := json.Marshal(map[string]string{"email": email, "password": password})
	if err != nil {
		logger.Error("Failed to marshal registration data", logger.Fields{"component": "IDOR", "error": err})
		return "", fmt.Errorf("marshal registration data: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", registerURL, bytes.NewReader(regData))
	if err != nil {
		return "", fmt.Errorf("registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("registration: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read registration response body", logger.Fields{"component": "IDOR", "error": err})
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("registration failed: %s", string(body))
	}

	var result struct {
		Token   string `json:"token"`
		Session string `json:"session"`
		ID      string `json:"id"`
	}
	if err := json.Unmarshal(body, &result); err == nil {
		if result.Token != "" {
			return result.Token, nil
		}
		if result.Session != "" {
			return result.Session, nil
		}
		if result.ID != "" {
			return result.ID, nil
		}
	}

	return "", fmt.Errorf("no session token in registration response for %s", email)
}

func (i *IDORTwoAccount) createObjectAsVictim(ctx context.Context, targetURL, session, objectID string) (string, error) {
	// Validate target URL to prevent SSRF
	if err := security.ValidateURL(targetURL); err != nil {
		return "", fmt.Errorf("invalid target URL: %w", err)
	}
	createURL := targetURL + "/api/objects"

	logger.Info("Creating object as victim", logger.Fields{"component": "IDOR", "url": createURL})

	objData, err := json.Marshal(map[string]string{"name": objectID, "data": "sensitive"})
	if err != nil {
		logger.Error("Failed to marshal object data", logger.Fields{"component": "IDOR", "error": err})
		return "", fmt.Errorf("marshal object data: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", createURL, bytes.NewReader(objData))
	if err != nil {
		return "", fmt.Errorf("create object request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sanitizeSession(session))
	req.Header.Set("Authorization", "Bearer "+sanitizeSession(session))

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("create object: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read create object response body", logger.Fields{"component": "IDOR", "error": err})
	}
	return string(body), nil
}

func (i *IDORTwoAccount) accessObjectAsAttacker(ctx context.Context, targetURL, session, objectID, paramName string) (string, error) {
	// Validate target URL to prevent SSRF
	if err := security.ValidateURL(targetURL); err != nil {
		return "", fmt.Errorf("invalid target URL: %w", err)
	}
	accessURL := targetURL + fmt.Sprintf("/api/objects?%s=%s", paramName, objectID)

	logger.Info("Accessing object as attacker", logger.Fields{"component": "IDOR", "url": accessURL})

	req, err := http.NewRequestWithContext(ctx, "GET", accessURL, nil)
	if err != nil {
		return "", fmt.Errorf("access object request: %w", err)
	}
	req.Header.Set("Cookie", sanitizeSession(session))
	req.Header.Set("Authorization", "Bearer "+sanitizeSession(session))

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("access object: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read access object response body", logger.Fields{"component": "IDOR", "error": err})
	}
	return string(body), nil
}

func sanitizeSession(session string) string {
	// Remove characters that could be used for header injection
	session = strings.ReplaceAll(session, "\n", "")
	session = strings.ReplaceAll(session, "\r", "")
	session = strings.ReplaceAll(session, ":", "") // Colon separates header name and value
	return strings.TrimSpace(session)
}

func calculateSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}

	aLower := strings.ToLower(a)
	bLower := strings.ToLower(b)

	if aLower == bLower {
		return 1.0
	}

	common := 0
	for i := 0; i < len(aLower) && i < len(bLower); i++ {
		if aLower[i] == bLower[i] {
			common++
		}
	}

	maxLen := len(aLower)
	if len(bLower) > maxLen {
		maxLen = len(bLower)
	}

	if maxLen == 0 {
		return 0.0
	}

	return float64(common) / float64(maxLen)
}

func (r *IDORResult) String() string {
	return fmt.Sprintf("IDOR Result: Confirmed=%v, Severity=%s, VictimDataLen=%d, AttackerDataLen=%d",
		r.Confirmed, r.Severity, len(r.VictimData), len(r.AttackerData))
}
