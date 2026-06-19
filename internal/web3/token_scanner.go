package web3

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

type TokenScanner struct {
	client HTTPClient
}

type HTTPClient interface {
	Get(url string) ([]byte, error)
	Post(url string, body []byte) ([]byte, error)
}

func NewTokenScanner(client HTTPClient) *TokenScanner {
	return &TokenScanner{client: client}
}

func (s *TokenScanner) ScanToken(address string) TokenAnalysis {
	info := s.fetchTokenInfo(address)
	indicators := s.analyzeIndicators(info)

	score := s.calculateRugPullScore(indicators)
	riskLevel := s.determineRiskLevel(score)

	alerts, warnings := s.generateAlerts(indicators)

	return TokenAnalysis{
		Token:      info,
		Score:      score,
		RiskLevel:  riskLevel,
		Indicators: indicators,
		Alerts:     alerts,
		Warnings:   warnings,
		Timestamp:  time.Now(),
	}
}

func (s *TokenScanner) fetchTokenInfo(address string) TokenInfo {
	return TokenInfo{
		Address:      address,
		CreatedAt:    time.Now().Add(-72 * time.Hour),
		Creator:      "0x0000000000000000000000000000000000000000",
		Decimals:     18,
		TotalSupply:  "1000000000000000000000000",
		Holders:      42,
		OwnerAddress: "0x0000000000000000000000000000000000000001",
	}
}

func (s *TokenScanner) analyzeIndicators(info TokenInfo) RugPullIndicators {
	return RugPullIndicators{
		MintAuthority:     s.CheckMintAuthority(info),
		LpNotLocked:       !s.CheckLpLock(info),
		IsHoneypot:        s.CheckHoneypot(info),
		OwnerCanPause:     info.IsPausable,
		OwnerCanBlacklist: info.HasBlacklist,
		HighTax:           info.BuyTax > 5.0 || info.SellTax > 5.0,
		SuspiciousCreator: s.isSuspiciousCreator(info.Creator),
		NoRenounce:        !info.OwnerRenounced,
		CopycatToken:      s.isCopycatToken(info),
		FakeLiquidity:     s.hasFakeLiquidity(info),
	}
}

func (s *TokenScanner) CheckMintAuthority(info TokenInfo) bool {
	return info.IsMintable && !info.OwnerRenounced
}

func (s *TokenScanner) CheckLpLock(info TokenInfo) bool {
	return info.LpLocked && info.LpLockDuration >= 365
}

func (s *TokenScanner) CheckHoneypot(info TokenInfo) bool {
	return info.IsHoneypot
}

func (s *TokenScanner) CheckBondingCurve(info TokenInfo) bool {
	return info.HasTax && (info.BuyTax > info.SellTax*1.5)
}

func (s *TokenScanner) CheckOwnership(info TokenInfo) bool {
	return info.OwnerRenounced
}

func (s *TokenScanner) isSuspiciousCreator(creator string) bool {
	if creator == "0x0000000000000000000000000000000000000000" {
		return true
	}
	if strings.HasSuffix(strings.ToLower(creator), "dead") {
		return true
	}
	return false
}

func (s *TokenScanner) isCopycatToken(info TokenInfo) bool {
	knownTokens := map[string]bool{
		"WETH": true, "USDC": true, "USDT": true, "DAI": true,
		"WBTC": true, "LINK": true, "UNI": true, "AAVE": true,
	}
	return knownTokens[info.Symbol] && info.Holders < 100
}

func (s *TokenScanner) hasFakeLiquidity(info TokenInfo) bool {
	return info.LpLocked && info.LpLockDuration < 7
}

func (s *TokenScanner) calculateRugPullScore(indicators RugPullIndicators) float64 {
	score := 0.0

	if indicators.MintAuthority {
		score += 25.0
	}
	if indicators.LpNotLocked {
		score += 20.0
	}
	if indicators.IsHoneypot {
		score += 30.0
	}
	if indicators.OwnerCanPause {
		score += 10.0
	}
	if indicators.OwnerCanBlacklist {
		score += 10.0
	}
	if indicators.HighTax {
		score += 15.0
	}
	if indicators.SuspiciousCreator {
		score += 10.0
	}
	if indicators.NoRenounce {
		score += 15.0
	}
	if indicators.CopycatToken {
		score += 5.0
	}
	if indicators.FakeLiquidity {
		score += 20.0
	}

	return math.Min(score, 100.0)
}

func (s *TokenScanner) determineRiskLevel(score float64) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 50:
		return "HIGH"
	case score >= 30:
		return "MEDIUM"
	case score >= 10:
		return "LOW"
	default:
		return "INFO"
	}
}

func (s *TokenScanner) generateAlerts(indicators RugPullIndicators) ([]string, []string) {
	var alerts, warnings []string

	if indicators.MintAuthority {
		alerts = append(alerts, "Owner has mint authority - can create unlimited tokens")
	}
	if indicators.LpNotLocked {
		alerts = append(alerts, "Liquidity is not locked - owner can pull all LP")
	}
	if indicators.IsHoneypot {
		alerts = append(alerts, "Token appears to be a honeypot - selling may be blocked")
	}
	if indicators.HighTax {
		alerts = append(alerts, "High transaction tax detected (>5%)")
	}
	if indicators.FakeLiquidity {
		warnings = append(warnings, "Suspiciously short liquidity lock period")
	}
	if indicators.NoRenounce {
		warnings = append(warnings, "Ownership has not been renounced")
	}
	if indicators.OwnerCanPause {
		warnings = append(warnings, "Owner can pause trading")
	}
	if indicators.SuspiciousCreator {
		warnings = append(warnings, "Suspicious creator address")
	}
	if indicators.CopycatToken {
		warnings = append(warnings, "Token symbol matches popular token but has few holders")
	}

	return alerts, warnings
}

func (s *TokenScanner) GenerateReport(address string) TokenReport {
	analysis := s.ScanToken(address)

	scoreBreakdown := map[string]float64{
		"Mint Authority":  0,
		"LP Lock":         0,
		"Honeypot":        0,
		"Pause/Blacklist": 0,
		"Tax":             0,
		"Ownership":       0,
	}

	if analysis.Indicators.MintAuthority {
		scoreBreakdown["Mint Authority"] = 25.0
	}
	if analysis.Indicators.LpNotLocked {
		scoreBreakdown["LP Lock"] = 20.0
	}
	if analysis.Indicators.IsHoneypot {
		scoreBreakdown["Honeypot"] = 30.0
	}
	if analysis.Indicators.OwnerCanPause || analysis.Indicators.OwnerCanBlacklist {
		scoreBreakdown["Pause/Blacklist"] = 10.0
	}
	if analysis.Indicators.HighTax {
		scoreBreakdown["Tax"] = 15.0
	}
	if analysis.Indicators.NoRenounce {
		scoreBreakdown["Ownership"] = 15.0
	}

	summary := fmt.Sprintf("Token %s (%s) scored %.0f/100 - %s risk",
		analysis.Token.Symbol, analysis.Token.Address[:8], analysis.Score, analysis.RiskLevel)

	recommendation := "DYOR - Do Your Own Research"
	if analysis.RiskLevel == "CRITICAL" || analysis.RiskLevel == "HIGH" {
		recommendation = "HIGH RISK: Avoid this token. Multiple rug pull indicators detected."
	} else if analysis.RiskLevel == "MEDIUM" {
		recommendation = "MEDIUM RISK: Exercise extreme caution. Investigate further before investing."
	}

	var actions []string
	for _, alert := range analysis.Alerts {
		actions = append(actions, "ALERT: "+alert)
	}
	for _, warning := range analysis.Warnings {
		actions = append(actions, "WARNING: "+warning)
	}

	return TokenReport{
		Analysis:       analysis,
		Summary:        summary,
		Recommendation: recommendation,
		ScoreBreakdown: scoreBreakdown,
		Actions:        actions,
	}
}

func (s *TokenScanner) ScanTokenFromJSON(data []byte) (*TokenAnalysis, error) {
	var info TokenInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse token info: %w", err)
	}

	analysis := s.ScanToken(info.Address)
	analysis.Token = info
	return &analysis, nil
}
