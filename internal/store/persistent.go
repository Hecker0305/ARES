package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ares/engine/internal/security"
)

type AppSettings struct {
	InstanceName      string  `json:"instance_name"`
	MaxWorkers        int     `json:"max_workers"`
	EvidenceRetention string  `json:"evidence_retention"`
	ConfidenceGate    float64 `json:"confidence_gate"`
}

type SIEMPreset struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Endpoint  string `json:"endpoint"`
	APIMode   string `json:"apiMode"`
	Icon      string `json:"icon"`
	DocsURL   string `json:"docsUrl"`
	Enabled   bool   `json:"enabled"`
}

type WebhookSettings struct {
	URL         string                `json:"url"`
	Secret      security.SecretString `json:"secret"`
	Events      []string              `json:"events"`
	SIEMPresets []SIEMPreset          `json:"siemPresets,omitempty"`
}

type LLMModel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	BaseURL     string `json:"baseUrl"`
	Description string `json:"description"`
	MaxTokens   int    `json:"maxTokens,omitempty"`
	IsDefault   bool   `json:"isDefault,omitempty"`
}

type LLMSettings struct {
	Provider   string                `json:"provider"`
	Model      string                `json:"model"`
	BaseURL    string                `json:"base_url"`
	APIKey     security.SecretString `json:"api_key"`
	ModelID    string                `json:"modelId,omitempty"`
	Models     []LLMModel            `json:"models,omitempty"`
	MaxTokens  int                   `json:"maxTokens,omitempty"`
	Temperature float64              `json:"temperature,omitempty"`
}

type ScopeEntry struct {
	ID         string   `json:"id"`
	Target     string   `json:"target"`
	Tags       []string `json:"tags"`
	Authorized bool     `json:"authorized"`
	CreatedAt  string   `json:"created_at"`
}

type TeamMember struct {
	Email      string `json:"email"`
	Role       string `json:"role"`
	InvitedAt  string `json:"invited_at"`
	LastActive string `json:"last_active"`
}

type TicketingConfig struct {
	Provider string                `json:"provider"`
	URL      string                `json:"url"`
	Token    security.SecretString `json:"token"`
	Project  string                `json:"project"`
	Enabled  bool                  `json:"enabled"`
}

type BountyConfig struct {
	Platform string                `json:"platform"`
	Token    security.SecretString `json:"token"`
	Enabled  bool                  `json:"enabled"`
	Username string                `json:"username"`
}

type RateLimitSettings struct {
	RequestsPerWindow int `json:"requestsPerWindow"`
	WindowSeconds     int `json:"windowSeconds"`
}

type DiscordSettings struct {
	WebhookURL      string `json:"webhookUrl"`
	MinimumSeverity string `json:"minimumSeverity"`
}

type AgentMailSettings struct {
	Pod    string                `json:"pod"`
	APIKey security.SecretString `json:"apiKey"`
	HasKey bool                  `json:"hasApiKey"`
}

type PersistentStore struct {
	mu        sync.RWMutex
	dataDir   string
	settings  AppSettings
	webhook   WebhookSettings
	llm       LLMSettings
	rateLimit RateLimitSettings
	discord   DiscordSettings
	agentMail AgentMailSettings
	scopes    []ScopeEntry
	team      []TeamMember
	ticket    TicketingConfig
	bounty    []BountyConfig
}

func NewPersistentStore(dataDir string) *PersistentStore {
	ps := &PersistentStore{
		dataDir: dataDir,
		settings: AppSettings{
			InstanceName:      "Ares Engine",
			MaxWorkers:        5,
			EvidenceRetention: "30d",
			ConfidenceGate:    0.5,
		},
		webhook: WebhookSettings{
			Events: []string{"finding_created", "scan_complete", "critical_alert"},
		},
		rateLimit: RateLimitSettings{
			RequestsPerWindow: 100,
			WindowSeconds:     60,
		},
		discord: DiscordSettings{
			WebhookURL:      "",
			MinimumSeverity: "medium",
		},
		agentMail: AgentMailSettings{
			Pod: "default",
		},
	}
	ps.loadAll()
	return ps
}

func (ps *PersistentStore) GetSettings() AppSettings {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.settings
}

func (ps *PersistentStore) SaveSettings(s AppSettings) {
	ps.mu.Lock()
	ps.settings = s
	ps.mu.Unlock()
	ps.save("settings.json", s)
}

func (ps *PersistentStore) GetWebhook() WebhookSettings {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.webhook
}

func (ps *PersistentStore) SaveWebhook(w WebhookSettings) {
	ps.mu.Lock()
	ps.webhook = w
	ps.mu.Unlock()
	ps.save("webhook.json", w)
}

func (ps *PersistentStore) GetLLM() LLMSettings {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.llm
}

func (ps *PersistentStore) SaveLLM(l LLMSettings) {
	ps.mu.Lock()
	ps.llm = l
	ps.mu.Unlock()
	ps.save("llm.json", l)
}

func (ps *PersistentStore) ListScopes() []ScopeEntry {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return append([]ScopeEntry{}, ps.scopes...)
}

func (ps *PersistentStore) AddScope(target string, tags []string) (ScopeEntry, error) {
	if target == "" {
		return ScopeEntry{}, fmt.Errorf("target is required")
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	id, err := generateSecureID("scope")
	if err != nil {
		return ScopeEntry{}, fmt.Errorf("failed to generate ID: %w", err)
	}
	entry := ScopeEntry{
		ID:         id,
		Target:     target,
		Tags:       tags,
		Authorized: true,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	ps.scopes = append(ps.scopes, entry)
	ps.save("scopes.json", ps.scopes)
	return entry, nil
}

func (ps *PersistentStore) DeleteScope(id string) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, s := range ps.scopes {
		if s.ID == id {
			ps.scopes = append(ps.scopes[:i], ps.scopes[i+1:]...)
			ps.save("scopes.json", ps.scopes)
			return true
		}
	}
	return false
}

func (ps *PersistentStore) ListTeam() []TeamMember {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return append([]TeamMember{}, ps.team...)
}

func (ps *PersistentStore) AddTeamMember(email, role string) (TeamMember, error) {
	if email == "" {
		return TeamMember{}, fmt.Errorf("email is required")
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	member := TeamMember{
		Email:      email,
		Role:       role,
		InvitedAt:  time.Now().UTC().Format(time.RFC3339),
		LastActive: "Never",
	}
	ps.team = append(ps.team, member)
	ps.save("team.json", ps.team)
	return member, nil
}

func (ps *PersistentStore) save(filename string, data interface{}) {
	if ps.dataDir == "" {
		return
	}
	path := ps.dataDir + "/" + filename
	os.MkdirAll(ps.dataDir, 0700)
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(path, jsonData, 0600)
}

func (ps *PersistentStore) GetRateLimit() RateLimitSettings {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.rateLimit
}

func (ps *PersistentStore) SaveRateLimit(r RateLimitSettings) {
	ps.mu.Lock()
	ps.rateLimit = r
	ps.mu.Unlock()
	ps.save("rate_limit.json", r)
}

func (ps *PersistentStore) GetDiscord() DiscordSettings {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.discord
}

func (ps *PersistentStore) SaveDiscord(d DiscordSettings) {
	ps.mu.Lock()
	ps.discord = d
	ps.mu.Unlock()
	ps.save("discord.json", d)
}

func (ps *PersistentStore) GetAgentMail() AgentMailSettings {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.agentMail
}

func (ps *PersistentStore) SaveAgentMail(a AgentMailSettings) {
	ps.mu.Lock()
	ps.agentMail = a
	ps.mu.Unlock()
	ps.save("agentmail.json", a)
}

func (ps *PersistentStore) loadAll() {
	ps.load("settings.json", &ps.settings)
	ps.load("webhook.json", &ps.webhook)
	ps.load("llm.json", &ps.llm)
	ps.load("rate_limit.json", &ps.rateLimit)
	ps.load("discord.json", &ps.discord)
	ps.load("agentmail.json", &ps.agentMail)
	ps.load("scopes.json", &ps.scopes)
	ps.load("team.json", &ps.team)
	ps.load("ticketing.json", &ps.ticket)
	ps.load("bounty.json", &ps.bounty)
}

func (ps *PersistentStore) load(filename string, target interface{}) {
	if ps.dataDir == "" {
		return
	}
	path := ps.dataDir + "/" + filename
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	json.Unmarshal(data, target)
}

func generateSecureID(prefix string) (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	ts := time.Now().UTC().Format("20060102150405")
	return prefix + "-" + ts + "-" + hex.EncodeToString(b), nil
}
