package web3

import (
	"testing"
)

type mockHTTPClient struct{}

func (m *mockHTTPClient) Get(url string) ([]byte, error) {
	return []byte(`{"address":"0x123","name":"TestToken","symbol":"TEST","decimals":18}`), nil
}

func (m *mockHTTPClient) Post(url string, body []byte) ([]byte, error) {
	return []byte(`{"status":"ok"}`), nil
}

func TestNewTokenScanner(t *testing.T) {
	client := &mockHTTPClient{}
	s := NewTokenScanner(client)
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestScanToken(t *testing.T) {
	client := &mockHTTPClient{}
	s := NewTokenScanner(client)

	analysis := s.ScanToken("0x1234567890abcdef")
	if analysis.Token.Address != "0x1234567890abcdef" {
		t.Errorf("expected address 0x1234567890abcdef, got %s", analysis.Token.Address)
	}
	if analysis.Score <= 0 {
		t.Error("expected positive score")
	}
	if analysis.RiskLevel == "" {
		t.Error("expected non-empty risk level")
	}
}

func TestCheckMintAuthority(t *testing.T) {
	s := NewTokenScanner(&mockHTTPClient{})

	tests := []struct {
		name     string
		info     TokenInfo
		expected bool
	}{
		{
			name:     "mintable and not renounced",
			info:     TokenInfo{IsMintable: true, OwnerRenounced: false},
			expected: true,
		},
		{
			name:     "not mintable",
			info:     TokenInfo{IsMintable: false, OwnerRenounced: false},
			expected: false,
		},
		{
			name:     "mintable but renounced",
			info:     TokenInfo{IsMintable: true, OwnerRenounced: true},
			expected: false,
		},
		{
			name:     "not mintable and renounced",
			info:     TokenInfo{IsMintable: false, OwnerRenounced: true},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.CheckMintAuthority(tc.info); got != tc.expected {
				t.Errorf("CheckMintAuthority() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestCheckLpLock(t *testing.T) {
	s := NewTokenScanner(&mockHTTPClient{})

	tests := []struct {
		name     string
		info     TokenInfo
		expected bool
	}{
		{
			name:     "locked for 365 days",
			info:     TokenInfo{LpLocked: true, LpLockDuration: 365},
			expected: true,
		},
		{
			name:     "locked for 30 days",
			info:     TokenInfo{LpLocked: true, LpLockDuration: 30},
			expected: false,
		},
		{
			name:     "not locked",
			info:     TokenInfo{LpLocked: false, LpLockDuration: 0},
			expected: false,
		},
		{
			name:     "locked for 500 days",
			info:     TokenInfo{LpLocked: true, LpLockDuration: 500},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.CheckLpLock(tc.info); got != tc.expected {
				t.Errorf("CheckLpLock() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestCheckHoneypot(t *testing.T) {
	s := NewTokenScanner(&mockHTTPClient{})

	if s.CheckHoneypot(TokenInfo{IsHoneypot: true}) != true {
		t.Error("expected true for honeypot")
	}
	if s.CheckHoneypot(TokenInfo{IsHoneypot: false}) != false {
		t.Error("expected false for non-honeypot")
	}
}

func TestCheckOwnership(t *testing.T) {
	s := NewTokenScanner(&mockHTTPClient{})

	if s.CheckOwnership(TokenInfo{OwnerRenounced: true}) != true {
		t.Error("expected true when renounced")
	}
	if s.CheckOwnership(TokenInfo{OwnerRenounced: false}) != false {
		t.Error("expected false when not renounced")
	}
}

func TestCalculateRugPullScore(t *testing.T) {
	s := NewTokenScanner(&mockHTTPClient{})

	tests := []struct {
		name       string
		indicators RugPullIndicators
		expected   float64
	}{
		{
			name: "all dangerous",
			indicators: RugPullIndicators{
				MintAuthority:     true,
				LpNotLocked:       true,
				IsHoneypot:        true,
				OwnerCanPause:     true,
				OwnerCanBlacklist: true,
				HighTax:           true,
				SuspiciousCreator: true,
				NoRenounce:        true,
				CopycatToken:      true,
				FakeLiquidity:     true,
			},
			expected: 100.0,
		},
		{
			name:       "no flags",
			indicators: RugPullIndicators{},
			expected:   0.0,
		},
		{
			name: "mint + no lp lock",
			indicators: RugPullIndicators{
				MintAuthority: true,
				LpNotLocked:   true,
			},
			expected: 45.0,
		},
		{
			name: "honeypot only",
			indicators: RugPullIndicators{
				IsHoneypot: true,
			},
			expected: 30.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := s.calculateRugPullScore(tc.indicators)
			if got != tc.expected {
				t.Errorf("calculateRugPullScore() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestDetermineRiskLevel(t *testing.T) {
	s := NewTokenScanner(&mockHTTPClient{})

	tests := []struct {
		score    float64
		expected string
	}{
		{85, "CRITICAL"},
		{70, "CRITICAL"},
		{60, "HIGH"},
		{50, "HIGH"},
		{40, "MEDIUM"},
		{30, "MEDIUM"},
		{20, "LOW"},
		{10, "LOW"},
		{5, "INFO"},
		{0, "INFO"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if got := s.determineRiskLevel(tc.score); got != tc.expected {
				t.Errorf("determineRiskLevel(%v) = %v, want %v", tc.score, got, tc.expected)
			}
		})
	}
}

func TestGenerateAlerts(t *testing.T) {
	s := NewTokenScanner(&mockHTTPClient{})

	indicators := RugPullIndicators{
		MintAuthority:     true,
		LpNotLocked:       true,
		IsHoneypot:        true,
		HighTax:           true,
		OwnerCanPause:     true,
		OwnerCanBlacklist: true,
		NoRenounce:        true,
		SuspiciousCreator: true,
		CopycatToken:      true,
		FakeLiquidity:     true,
	}

	alerts, warnings := s.generateAlerts(indicators)

	if len(alerts) == 0 {
		t.Error("expected at least some alerts")
	}
	if len(warnings) == 0 {
		t.Error("expected at least some warnings")
	}

	expectedAlerts := 4
	expectedWarnings := 5
	if len(alerts) != expectedAlerts {
		t.Errorf("expected %d alerts, got %d", expectedAlerts, len(alerts))
	}
	if len(warnings) != expectedWarnings {
		t.Errorf("expected %d warnings, got %d", expectedWarnings, len(warnings))
	}
}

func TestGenerateReport(t *testing.T) {
	client := &mockHTTPClient{}
	s := NewTokenScanner(client)

	report := s.GenerateReport("0xdead000000000000000000000000000000000000")
	if report.Summary == "" {
		t.Error("expected non-empty summary")
	}
	if report.Recommendation == "" {
		t.Error("expected non-empty recommendation")
	}
	if len(report.ScoreBreakdown) == 0 {
		t.Error("expected score breakdown")
	}
	if report.Analysis.Token.Address != "0xdead000000000000000000000000000000000000" {
		t.Errorf("expected address to match, got %s", report.Analysis.Token.Address)
	}
}

func TestScanTokenFromJSON(t *testing.T) {
	client := &mockHTTPClient{}
	s := NewTokenScanner(client)

	data := []byte(`{"address":"0xabc","name":"Test","symbol":"TST","decimals":18}`)
	analysis, err := s.ScanTokenFromJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if analysis.Token.Name != "Test" {
		t.Errorf("expected Test, got %s", analysis.Token.Name)
	}
}

func TestScanTokenFromJSON_Invalid(t *testing.T) {
	client := &mockHTTPClient{}
	s := NewTokenScanner(client)

	_, err := s.ScanTokenFromJSON([]byte(`{invalid}`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestIsSuspiciousCreator(t *testing.T) {
	s := NewTokenScanner(&mockHTTPClient{})

	tests := []struct {
		creator  string
		expected bool
	}{
		{"0x0000000000000000000000000000000000000000", true},
		{"0x000000000000000000000000000000000000dEaD", true},
		{"0x1234567890abcdef1234567890abcdef12345678", false},
	}

	for _, tc := range tests {
		t.Run(tc.creator, func(t *testing.T) {
			if got := s.isSuspiciousCreator(tc.creator); got != tc.expected {
				t.Errorf("isSuspiciousCreator(%q) = %v, want %v", tc.creator, got, tc.expected)
			}
		})
	}
}

func TestIsCopycatToken(t *testing.T) {
	s := NewTokenScanner(&mockHTTPClient{})

	tests := []struct {
		name     string
		info     TokenInfo
		expected bool
	}{
		{
			name:     "WETH with few holders",
			info:     TokenInfo{Symbol: "WETH", Holders: 10},
			expected: true,
		},
		{
			name:     "WETH with many holders",
			info:     TokenInfo{Symbol: "WETH", Holders: 1000},
			expected: false,
		},
		{
			name:     "unknown token",
			info:     TokenInfo{Symbol: "RANDOM", Holders: 5},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.isCopycatToken(tc.info); got != tc.expected {
				t.Errorf("isCopycatToken() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestHasFakeLiquidity(t *testing.T) {
	s := NewTokenScanner(&mockHTTPClient{})

	tests := []struct {
		name     string
		info     TokenInfo
		expected bool
	}{
		{
			name:     "locked 1 day",
			info:     TokenInfo{LpLocked: true, LpLockDuration: 1},
			expected: true,
		},
		{
			name:     "locked 6 days",
			info:     TokenInfo{LpLocked: true, LpLockDuration: 6},
			expected: true,
		},
		{
			name:     "locked 7 days",
			info:     TokenInfo{LpLocked: true, LpLockDuration: 7},
			expected: false,
		},
		{
			name:     "not locked",
			info:     TokenInfo{LpLocked: false, LpLockDuration: 0},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.hasFakeLiquidity(tc.info); got != tc.expected {
				t.Errorf("hasFakeLiquidity() = %v, want %v", got, tc.expected)
			}
		})
	}
}
