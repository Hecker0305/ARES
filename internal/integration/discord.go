package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type DiscordWebhook struct {
	URL       string
	Username  string
	AvatarURL string
	client    *http.Client
}

type discordPayload struct {
	Content   string         `json:"content,omitempty"`
	Username  string         `json:"username,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
	Embeds    []discordEmbed `json:"embeds,omitempty"`
}

type discordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []discordEmbedField `json:"fields"`
	Timestamp   string              `json:"timestamp"`
}

type discordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

func NewDiscordWebhook(url string) *DiscordWebhook {
	return &DiscordWebhook{
		URL:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *DiscordWebhook) SendFinding(target, findingType, severity, description string) error {
	color := 0x5865F2
	switch severity {
	case "critical":
		color = 0xED4245
	case "high":
		color = 0xFFA500
	case "medium":
		color = 0xFEE75C
	case "low":
		color = 0x57F287
	}

	payload := discordPayload{
		Username:  d.Username,
		AvatarURL: d.AvatarURL,
		Embeds: []discordEmbed{{
			Title:       fmt.Sprintf("Finding: %s", findingType),
			Description: description,
			Color:       color,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Fields: []discordEmbedField{
				{Name: "Target", Value: target, Inline: true},
				{Name: "Severity", Value: severity, Inline: true},
			},
		}},
	}
	return d.send(payload)
}

func (d *DiscordWebhook) SendScanStatus(target, status string, findingCount int) error {
	payload := discordPayload{
		Username:  d.Username,
		AvatarURL: d.AvatarURL,
		Embeds: []discordEmbed{{
			Title:       fmt.Sprintf("Scan %s", status),
			Description: fmt.Sprintf("Scan for **%s** is now **%s**", target, status),
			Color:       0x5865F2,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Fields: []discordEmbedField{
				{Name: "Target", Value: target, Inline: true},
				{Name: "Findings", Value: fmt.Sprintf("%d", findingCount), Inline: true},
			},
		}},
	}
	return d.send(payload)
}

func (d *DiscordWebhook) send(payload discordPayload) error {
	if d.URL == "" {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	resp, err := d.client.Post(d.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord returned %d", resp.StatusCode)
	}
	return nil
}
