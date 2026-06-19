package web3

import (
	"encoding/json"
	"time"
)

type VulnerabilityClass string

const (
	VulnAccountingDesync      VulnerabilityClass = "accounting-desync"
	VulnAccessControl         VulnerabilityClass = "access-control"
	VulnIncompleteCodePath    VulnerabilityClass = "incomplete-code-path"
	VulnOffByOne              VulnerabilityClass = "off-by-one"
	VulnOracleManipulation    VulnerabilityClass = "oracle-manipulation"
	VulnERC4626ShareInflation VulnerabilityClass = "erc4626-share-inflation"
	VulnReentrancy            VulnerabilityClass = "reentrancy"
	VulnFlashLoanAttack       VulnerabilityClass = "flash-loan-attack"
	VulnSignatureReplay       VulnerabilityClass = "signature-replay"
	VulnProxyUpgrade          VulnerabilityClass = "proxy-upgrade"
)

type Severity int

const (
	SevInfo     Severity = 0
	SevLow      Severity = 1
	SevMedium   Severity = 2
	SevHigh     Severity = 3
	SevCritical Severity = 4
)

type ContractInfo struct {
	Address       string          `json:"address"`
	Source        string          `json:"source"`
	Compiler      string          `json:"compiler"`
	CompilerVer   string          `json:"compiler_version"`
	ABI           json.RawMessage `json:"abi,omitempty"`
	Bytecode      string          `json:"bytecode,omitempty"`
	DeployTx      string          `json:"deploy_tx,omitempty"`
	DeployedAt    time.Time       `json:"deployed_at,omitempty"`
	ChainID       int             `json:"chain_id"`
	TokenStandard string          `json:"token_standard,omitempty"`
	IsVerified    bool            `json:"is_verified"`
	License       string          `json:"license,omitempty"`
	SWCRecords    []string        `json:"swc_records,omitempty"`
	SlitherOutput json.RawMessage `json:"slither_output,omitempty"`
	MythrilOutput json.RawMessage `json:"mythril_output,omitempty"`
}

type SourceCode struct {
	Language   string            `json:"language"`
	Source     string            `json:"source"`
	Files      map[string]string `json:"files,omitempty"`
	EntryPoint string            `json:"entry_point"`
	Imports    []string          `json:"imports,omitempty"`
	Pragma     string            `json:"pragma,omitempty"`
	Libraries  []string          `json:"libraries,omitempty"`
}

type AuditResult struct {
	Class        VulnerabilityClass `json:"class"`
	Title        string             `json:"title"`
	Description  string             `json:"description"`
	Severity     Severity           `json:"severity"`
	Confidence   float64            `json:"confidence"`
	Location     string             `json:"location"`
	LineStart    int                `json:"line_start"`
	LineEnd      int                `json:"line_end"`
	PoC          string             `json:"poc,omitempty"`
	Remediation  string             `json:"remediation,omitempty"`
	SWC          string             `json:"swc,omitempty"`
	CWE          string             `json:"cwe,omitempty"`
	References   []string           `json:"references,omitempty"`
	SubCategory  string             `json:"sub_category,omitempty"`
	Impact       string             `json:"impact,omitempty"`
	Likelihood   int                `json:"likelihood"`
	GasOptimized bool               `json:"gas_optimized"`
}

type TokenInfo struct {
	Address        string    `json:"address"`
	Name           string    `json:"name"`
	Symbol         string    `json:"symbol"`
	Decimals       int       `json:"decimals"`
	TotalSupply    string    `json:"total_supply"`
	Holders        int       `json:"holders"`
	OwnerAddress   string    `json:"owner_address"`
	IsMintable     bool      `json:"is_mintable"`
	IsPausable     bool      `json:"is_pausable"`
	IsBurnable     bool      `json:"is_burnable"`
	HasTax         bool      `json:"has_tax"`
	BuyTax         float64   `json:"buy_tax"`
	SellTax        float64   `json:"sell_tax"`
	LpLocked       bool      `json:"lp_locked"`
	LpLockDuration int       `json:"lp_lock_duration_days"`
	LpHolder       string    `json:"lp_holder,omitempty"`
	IsHoneypot     bool      `json:"is_honeypot"`
	OwnerRenounced bool      `json:"owner_renounced"`
	HasBlacklist   bool      `json:"has_blacklist"`
	HasWhitelist   bool      `json:"has_whitelist"`
	IsProxy        bool      `json:"is_proxy"`
	Implementation string    `json:"implementation,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	Creator        string    `json:"creator"`
}

type RugPullIndicators struct {
	MintAuthority     bool     `json:"mint_authority"`
	LpNotLocked       bool     `json:"lp_not_locked"`
	IsHoneypot        bool     `json:"is_honeypot"`
	OwnerCanPause     bool     `json:"owner_can_pause"`
	OwnerCanBlacklist bool     `json:"owner_can_blacklist"`
	HighTax           bool     `json:"high_tax"`
	SuspiciousCreator bool     `json:"suspicious_creator"`
	NoRenounce        bool     `json:"no_renounce"`
	CopycatToken      bool     `json:"copycat_token"`
	FakeLiquidity     bool     `json:"fake_liquidity"`
	RugPullScore      float64  `json:"rug_pull_score"`
	RiskLevel         string   `json:"risk_level"`
	WarningCount      int      `json:"warning_count"`
	Flags             []string `json:"flags"`
}

type TokenAnalysis struct {
	Token      TokenInfo         `json:"token"`
	Score      float64           `json:"score"`
	RiskLevel  string            `json:"risk_level"`
	Indicators RugPullIndicators `json:"indicators"`
	Alerts     []string          `json:"alerts"`
	Warnings   []string          `json:"warnings"`
	Timestamp  time.Time         `json:"timestamp"`
}

type TokenReport struct {
	Analysis       TokenAnalysis      `json:"analysis"`
	Summary        string             `json:"summary"`
	Recommendation string             `json:"recommendation"`
	ScoreBreakdown map[string]float64 `json:"score_breakdown"`
	Actions        []string           `json:"actions,omitempty"`
}
