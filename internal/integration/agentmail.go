package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type AgentMail struct {
	baseURL    string
	httpClient *http.Client
}

type InboxResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type MessageResponse struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	Subject    string `json:"subject"`
	Body       string `json:"body"`
	HTML       string `json:"html"`
	ReceivedAt string `json:"received_at"`
}

func NewAgentMail() *AgentMail {
	return &AgentMail{
		baseURL: "https://api.agentmail.to",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (a *AgentMail) GenerateInbox() (*InboxResponse, error) {
	resp, err := a.httpClient.Post(a.baseURL+"/v1/inboxes", "application/json", nil)
	if err != nil {
		return nil, fmt.Errorf("agentmail: create inbox: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("agentmail: read response: %w", err)
	}

	var inbox InboxResponse
	if err := json.Unmarshal(body, &inbox); err != nil {
		return nil, fmt.Errorf("agentmail: parse inbox: %w (body: %s)", err, string(body))
	}
	return &inbox, nil
}

func (a *AgentMail) WaitForMessage(inboxID string, timeoutSec int) (*MessageResponse, error) {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	pollInterval := 2 * time.Second

	for time.Now().Before(deadline) {
		url := fmt.Sprintf("%s/v1/inboxes/%s/messages", a.baseURL, inboxID)
		resp, err := a.httpClient.Get(url)
		if err != nil {
			return nil, fmt.Errorf("agentmail: fetch messages: %w", err)
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var messages []MessageResponse
		if err := json.Unmarshal(body, &messages); err == nil && len(messages) > 0 {
			return &messages[0], nil
		}

		time.Sleep(pollInterval)
	}
	return nil, fmt.Errorf("agentmail: timeout waiting for message in inbox %s", inboxID)
}

func (a *AgentMail) ExtractOTP(content string) string {
	patterns := []string{
		`\b(\d{4,8})\b`,
		`\b(OTP|otp|code|verification|pin|token)[:\s]*(\d{4,8})\b`,
		`\b(\d{6})\b`,
	}
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(content)
		if len(matches) > 1 {
			for i := len(matches) - 1; i >= 1; i-- {
				val := strings.TrimSpace(matches[i])
				if len(val) >= 4 && len(val) <= 8 {
					onlyDigits := true
					for _, c := range val {
						if c < '0' || c > '9' {
							onlyDigits = false
							break
						}
					}
					if onlyDigits {
						return val
					}
				}
			}
		}
	}
	return ""
}

func (a *AgentMail) DeleteInbox(inboxID string) error {
	req, err := http.NewRequest(http.MethodDelete, a.baseURL+"/v1/inboxes/"+inboxID, nil)
	if err != nil {
		return fmt.Errorf("agentmail: delete request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agentmail: delete inbox: %w", err)
	}
	resp.Body.Close()
	return nil
}
