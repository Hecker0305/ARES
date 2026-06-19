package web3

import (
	"fmt"
	"regexp"
	"strings"
)

type Auditor struct {
	contract      SourceCode
	results       []AuditResult
	slitherOutput string
	mythrilOutput string
}

func NewAuditor() *Auditor {
	return &Auditor{}
}

func (a *Auditor) Audit(contract SourceCode) []AuditResult {
	a.contract = contract
	a.results = nil

	a.CheckAccessControl()
	a.CheckReentrancy()
	a.CheckOracleManipulation()
	a.CheckFlashLoan()
	a.CheckSignatureReplay()
	a.CheckProxyUpgrade()
	a.CheckAccountingDesync()
	a.CheckIncompleteCodePath()
	a.CheckOffByOne()
	a.CheckERC4626Inflation()

	return a.results
}

func (a *Auditor) addResult(r AuditResult) {
	a.results = append(a.results, r)
}

func (a *Auditor) CheckAccessControl() {
	src := a.contract.Source

	if strings.Contains(src, "tx.origin") {
		a.addResult(AuditResult{
			Class:       VulnAccessControl,
			Title:       "tx.origin used for authorization",
			Description: "tx.origin should not be used for access control as it can be manipulated via intermediate contract calls. Use msg.sender instead.",
			Severity:    SevHigh,
			Confidence:  0.9,
			Remediation: "Replace tx.origin with msg.sender for access control checks",
			SWC:         "SWC-115",
			CWE:         "CWE-283",
		})
	}

	if strings.Contains(src, "delegatecall") && !strings.Contains(src, "onlyOwner") && !strings.Contains(src, "onlyProxy") {
		a.addResult(AuditResult{
			Class:       VulnAccessControl,
			Title:       "delegatecall without access control",
			Description: "delegatecall is used but no access control modifier was detected. This could allow unauthorized storage manipulation.",
			Severity:    SevCritical,
			Confidence:  0.7,
			Remediation: "Add OpenZeppelin's onlyOwner or custom access control to functions using delegatecall",
			SWC:         "SWC-112",
		})
	}

	exposedFns := []string{"initialize", "init", "__init"}
	for _, fn := range exposedFns {
		pattern := fmt.Sprintf(`function\s+%s\s*\(`, fn)
		re := regexp.MustCompile(pattern)
		if re.MatchString(src) {
			if !strings.Contains(src, "initializer") {
				a.addResult(AuditResult{
					Class:       VulnAccessControl,
					Title:       fmt.Sprintf("Unprotected initialize function: %s()", fn),
					Description: "The initialize function lacks the initializer modifier and could be called multiple times to reinitialize the contract.",
					Severity:    SevCritical,
					Confidence:  0.85,
					Remediation: "Add OpenZeppelin's initializer modifier to the initialize function",
					SWC:         "SWC-118",
				})
			}
		}
	}

	selfdestructRe := regexp.MustCompile(`selfdestruct\s*\(`)
	if selfdestructRe.MatchString(src) {
		if !strings.Contains(src, "onlyOwner") && !strings.Contains(src, "onlyAdmin") {
			a.addResult(AuditResult{
				Class:       VulnAccessControl,
				Title:       "selfdestruct without access control",
				Description: "selfdestruct is called without access control protection, allowing anyone to destroy the contract.",
				Severity:    SevCritical,
				Confidence:  0.9,
				Remediation: "Add onlyOwner or equivalent access control to selfdestruct calls",
				SWC:         "SWC-106",
			})
		}
	}
}

func (a *Auditor) CheckReentrancy() {
	src := a.contract.Source

	hasCall := strings.Contains(src, ".call{") || strings.Contains(src, ".call(")
	hasStateChange := strings.Contains(src, "balance[") || strings.Contains(src, "balances[") || strings.Contains(src, "mapping")
	hasReentrancyGuard := strings.Contains(src, "nonReentrant") || strings.Contains(src, "ReentrancyGuard") || strings.Contains(src, "mutex")

	if hasCall && hasStateChange && !hasReentrancyGuard {
		a.addResult(AuditResult{
			Class:       VulnReentrancy,
			Title:       "Potential reentrancy vulnerability",
			Description: "External call detected before state changes without reentrancy protection. This could allow reentrancy attacks.",
			Severity:    SevHigh,
			Confidence:  0.75,
			Remediation: "Apply checks-effects-interactions pattern or use OpenZeppelin's ReentrancyGuard",
			SWC:         "SWC-107",
			CWE:         "CWE-841",
		})
	}

	if strings.Contains(src, "msg.sender.call") && strings.Contains(src, "withdraw") {
		a.addResult(AuditResult{
			Class:       VulnReentrancy,
			Title:       "Reentrancy in withdraw function",
			Description: "withdraw function uses msg.sender.call which forwards all gas and can trigger reentrancy in the fallback function.",
			Severity:    SevCritical,
			Confidence:  0.9,
			Remediation: "Update state before making external calls and add a reentrancy guard",
			SWC:         "SWC-107",
		})
	}

	if strings.Contains(src, ".delegatecall(") && strings.Contains(src, "fallback") {
		a.addResult(AuditResult{
			Class:       VulnReentrancy,
			Title:       "Reentrancy via fallback with delegatecall",
			Description: "Fallback function performs delegatecall which can allow reentrancy through the delegatecall context.",
			Severity:    SevHigh,
			Confidence:  0.8,
			Remediation: "Add reentrancy guard to the fallback function or avoid delegatecall in fallback",
			SWC:         "SWC-107",
		})
	}
}

func (a *Auditor) CheckOracleManipulation() {
	src := a.contract.Source

	if strings.Contains(src, "getReserve") || strings.Contains(src, "getAmountsOut") || strings.Contains(src, "getAmountOut") {
		if !strings.Contains(src, "TWAP") && !strings.Contains(src, "twap") && !strings.Contains(src, "oracle") {
			a.addResult(AuditResult{
				Class:       VulnOracleManipulation,
				Title:       "Spot price oracle manipulation risk",
				Description: "Contract uses spot price from a DEX (getReserves/getAmountsOut) without TWAP or oracle validation. Spot prices can be manipulated via flash loans.",
				Severity:    SevHigh,
				Confidence:  0.8,
				Remediation: "Use a TWAP oracle like Chainlink or Uniswap V3 TWAP instead of spot price",
				SWC:         "SWC-120",
				References:  []string{"https://docs.chain.link/data-feeds"},
			})
		}
	}

	if strings.Contains(src, "block.prevrandao") || strings.Contains(src, "block.difficulty") || strings.Contains(src, "blockhash") {
		a.addResult(AuditResult{
			Class:       VulnOracleManipulation,
			Title:       "Weak randomness source",
			Description: "block.prevrandao/difficulty/blockhash should not be used as randomness sources as they can be manipulated by miners/validators.",
			Severity:    SevMedium,
			Confidence:  0.85,
			Remediation: "Use a verifiable randomness source like Chainlink VRF",
			SWC:         "SWC-120",
			References:  []string{"https://docs.chain.link/vrf"},
		})
	}

	priceRe := regexp.MustCompile(`(price|rate|value)\s*[=:]\s*.*price|rate|value`)
	if priceRe.MatchString(src) {
		if !strings.Contains(src, "chainlink") && !strings.Contains(src, "oracle") {
			a.addResult(AuditResult{
				Class:       VulnOracleManipulation,
				Title:       "Unvalidated price feed",
				Description: "Price/value assignment detected without Chainlink or oracle validation. The price source should be verified.",
				Severity:    SevLow,
				Confidence:  0.5,
				Remediation: "Use a Chainlink price feed or verify the price source is secure",
				SWC:         "SWC-120",
			})
		}
	}
}

func (a *Auditor) CheckFlashLoan() {
	src := a.contract.Source

	if strings.Contains(src, "flashLoan") || strings.Contains(src, "flash_loan") || strings.Contains(src, "flashloan") {
		if !strings.Contains(src, "fee") && !strings.Contains(src, "premium") {
			a.addResult(AuditResult{
				Class:       VulnFlashLoanAttack,
				Title:       "Flash loan function without fee",
				Description: "Flash loan function detected without a fee or premium. Flash loans without fees can be used for economic attacks.",
				Severity:    SevMedium,
				Confidence:  0.7,
				Remediation: "Implement a flash loan fee following the ERC-3156 standard",
				SWC:         "SWC-120",
			})
		}
	}

	if strings.Contains(src, "IUniswapV2Callee") || strings.Contains(src, "uniswapV2Call") || strings.Contains(src, "IUniswapV3FlashCallback") {
		if strings.Contains(src, "balance[") || strings.Contains(src, "balanceOf") {
			a.addResult(AuditResult{
				Class:       VulnFlashLoanAttack,
				Title:       "Flash loan callback manipulates balances",
				Description: "The flash loan callback function modifies contract state/balances, which could be exploited for price manipulation attacks.",
				Severity:    SevHigh,
				Confidence:  0.8,
				Remediation: "Separate flash loan logic from balance-dependent operations, add access control to callback functions",
				SWC:         "SWC-120",
			})
		}
	}
}

func (a *Auditor) CheckSignatureReplay() {
	src := a.contract.Source

	hasEcrecover := strings.Contains(src, "ecrecover") || strings.Contains(src, "ECDSA")
	hasNonce := strings.Contains(src, "nonce") || strings.Contains(src, "usedNonces")
	hasSigReplayGuard := strings.Contains(src, "nonces[") || strings.Contains(src, "usedNonces[") || strings.Contains(src, "isValidSignatureNow")

	if hasEcrecover && !hasNonce && !hasSigReplayGuard {
		a.addResult(AuditResult{
			Class:       VulnSignatureReplay,
			Title:       "Signature without nonce/replay protection",
			Description: "EIP-712 or ecrecover signature verification detected without nonce tracking. Signatures can be replayed across chains or multiple times.",
			Severity:    SevHigh,
			Confidence:  0.8,
			Remediation: "Add a nonce tracking mechanism and include chainId and contract address in the signed message",
			SWC:         "SWC-121",
			CWE:         "CWE-294",
		})
	}

	if hasEcrecover {
		if !strings.Contains(src, "block.chainid") && !strings.Contains(src, "chainId") && !strings.Contains(src, "DOMAIN_SEPARATOR") {
			a.addResult(AuditResult{
				Class:       VulnSignatureReplay,
				Title:       "Signature missing chainId protection",
				Description: "Signature verification does not include chainId in the signed data, allowing cross-chain replay attacks.",
				Severity:    SevMedium,
				Confidence:  0.75,
				Remediation: "Include block.chainid in the EIP-712 domain separator",
				SWC:         "SWC-121",
			})
		}
	}
}

func (a *Auditor) CheckProxyUpgrade() {
	src := a.contract.Source

	if strings.Contains(src, "delegatecall") && !strings.Contains(src, "upgradeTo") && !strings.Contains(src, "UUPS") && !strings.Contains(src, "TransparentUpgradeableProxy") {
		a.addResult(AuditResult{
			Class:       VulnProxyUpgrade,
			Title:       "Unupgradeable delegatecall proxy",
			Description: "delegatecall is used but no upgrade mechanism detected. The proxy logic cannot be upgraded without redeployment.",
			Severity:    SevLow,
			Confidence:  0.5,
			Remediation: "Implement UUPS or Transparent proxy pattern for upgradeability",
			SWC:         "SWC-125",
		})
	}

	if strings.Contains(src, "upgradeTo") {
		if !strings.Contains(src, "onlyOwner") && !strings.Contains(src, "onlyAdmin") && !strings.Contains(src, "onlyProxyAdmin") {
			a.addResult(AuditResult{
				Class:       VulnProxyUpgrade,
				Title:       "Unauthorized proxy upgrade function",
				Description: "upgradeTo function lacks access control, allowing anyone to upgrade the proxy implementation.",
				Severity:    SevCritical,
				Confidence:  0.9,
				Remediation: "Add onlyOwner or onlyProxyAdmin modifier to upgradeTo functions",
				SWC:         "SWC-125",
			})
		}
	}

	if strings.Contains(src, "initialize") && strings.Contains(src, "delegatecall") {
		if !strings.Contains(src, "initializer") && !strings.Contains(src, "_initialized") && !strings.Contains(src, "_initializing") {
			a.addResult(AuditResult{
				Class:       VulnProxyUpgrade,
				Title:       "Proxy initialize without initializer guard",
				Description: "Contract can be reinitialized in the proxy context, potentially allowing storage corruption.",
				Severity:    SevHigh,
				Confidence:  0.85,
				Remediation: "Use OpenZeppelin's Initializable base contract and initializer modifier",
				SWC:         "SWC-118",
			})
		}
	}

	storageCollisionRe := regexp.MustCompile(`(uint256|address|bool)\s+private\s+_.*(implementation|admin|owner)`)
	matches := storageCollisionRe.FindAllString(src, -1)
	if len(matches) > 0 && strings.Contains(src, "delegatecall") {
		a.addResult(AuditResult{
			Class:       VulnProxyUpgrade,
			Title:       "Potential proxy storage collision",
			Description: "Private variables detected that might collide with proxy storage slots. Ensure proper storage gap is implemented.",
			Severity:    SevMedium,
			Confidence:  0.6,
			Remediation: "Add __gap array for upgradeable contract storage layout",
			SWC:         "SWC-124",
		})
	}
}

func (a *Auditor) CheckAccountingDesync() {
	src := a.contract.Source

	if strings.Contains(src, "transfer") && strings.Contains(src, "balanceOf") {
		hasInternalAccounting := strings.Contains(src, "balance[") || strings.Contains(src, "balances[") || strings.Contains(src, "_balances")
		if !hasInternalAccounting {
			a.addResult(AuditResult{
				Class:       VulnAccountingDesync,
				Title:       "ERC20 balanceOf uses external source",
				Description: "Contract reads balanceOf from an external contract while performing transfers. This can desync with internal accounting.",
				Severity:    SevMedium,
				Confidence:  0.6,
				Remediation: "Maintain internal balance tracking that mirrors external balance updates",
				SWC:         "SWC-114",
			})
		}
	}

	shareAccounting := strings.Contains(src, "totalSupply") && strings.Contains(src, "balanceOf") && strings.Contains(src, "deposit")
	hasDesyncRisk := strings.Contains(src, "mint") || strings.Contains(src, "burn")
	if shareAccounting && hasDesyncRisk && !strings.Contains(src, "_update") && !strings.Contains(src, "_mint") && !strings.Contains(src, "_burn") {
		a.addResult(AuditResult{
			Class:       VulnAccountingDesync,
			Title:       "Manual mint/burn may desync accounting",
			Description: "Direct mint/burn operations detected without using _update/_mint/_burn helpers. This can cause share price accounting errors.",
			Severity:    SevHigh,
			Confidence:  0.7,
			Remediation: "Use OpenZeppelin's _mint and _burn internal functions for all supply changes",
			SWC:         "SWC-114",
		})
	}
}

func (a *Auditor) CheckIncompleteCodePath() {
	src := a.contract.Source

	revertWithoutReason := strings.Contains(src, "revert()") || strings.Contains(src, "revert;")
	if revertWithoutReason {
		a.addResult(AuditResult{
			Class:       VulnIncompleteCodePath,
			Title:       "Bare revert without reason string",
			Description: "revert() statements without reason strings make debugging difficult and may hide error conditions.",
			Severity:    SevLow,
			Confidence:  0.9,
			Remediation: "Add reason strings to all revert statements: revert('description')",
		})
	}

	assertRe := regexp.MustCompile(`assert\s*\(`)
	if assertRe.MatchString(src) {
		a.addResult(AuditResult{
			Class:       VulnIncompleteCodePath,
			Title:       "assert() used instead of require()",
			Description: "assert() consumes all gas on failure and should be used only for invariant testing. Use require() for input validation.",
			Severity:    SevLow,
			Confidence:  0.85,
			Remediation: "Replace assert() with require() for input validation and access control",
			SWC:         "SWC-110",
		})
	}

	todoRe := regexp.MustCompile(`(?i)(TODO|FIXME|HACK|XXX|UNDONE)`)
	unimplemented := todoRe.FindAllString(src, -1)
	if len(unimplemented) > 0 {
		a.addResult(AuditResult{
			Class:       VulnIncompleteCodePath,
			Title:       "Unimplemented code paths detected",
			Description: fmt.Sprintf("Found %d TODO/FIXME/HACK markers in the code that indicate incomplete implementation: %s", len(unimplemented), strings.Join(unimplemented, ", ")),
			Severity:    SevMedium,
			Confidence:  0.95,
			Remediation: "Review and implement all marked code paths before deployment",
		})
	}

	emptyFnRe := regexp.MustCompile(`function\s+\w+\s*\([^)]*\)\s*(public|external|internal|private)\s*\{\s*\}`)
	emptyFns := emptyFnRe.FindAllString(src, -1)
	if len(emptyFns) > 0 {
		a.addResult(AuditResult{
			Class:       VulnIncompleteCodePath,
			Title:       "Empty function bodies detected",
			Description: fmt.Sprintf("Found %d functions with empty bodies that may represent incomplete implementation", len(emptyFns)),
			Severity:    SevMedium,
			Confidence:  0.8,
			Remediation: "Implement all function bodies or remove unused function stubs",
		})
	}
}

func (a *Auditor) CheckOffByOne() {
	src := a.contract.Source

	offByOnePatterns := []struct {
		pattern *regexp.Regexp
		desc    string
	}{
		{regexp.MustCompile(`>\s*=\s*\.length`), "Array access uses >= .length which may cause out-of-bounds access"},
		{regexp.MustCompile(`<\s*=\s*\.length`), "Array comparison uses <= .length which could include one extra element"},
		{regexp.MustCompile(`>=\s*\.length`), "Array boundary check uses >= length instead of > length - 1"},
	}

	for _, p := range offByOnePatterns {
		if p.pattern.MatchString(src) {
			a.addResult(AuditResult{
				Class:       VulnOffByOne,
				Title:       "Potential off-by-one in array boundary check",
				Description: p.desc,
				Severity:    SevMedium,
				Confidence:  0.6,
				Remediation: "Use < .length instead of <= .length for array boundary checks",
				CWE:         "CWE-193",
			})
		}
	}

	loopRe := regexp.MustCompile(`for\s*\(\s*(uint|int)\s+\w+\s*=\s*0\s*;\s*\w+\s*<=\s*\w+\.length\s*;`)
	if loopRe.MatchString(src) {
		a.addResult(AuditResult{
			Class:       VulnOffByOne,
			Title:       "Loop iterates with <= .length",
			Description: "For loop uses <= .length as termination condition, causing an off-by-one overflow that reads beyond the array.",
			Severity:    SevHigh,
			Confidence:  0.8,
			Remediation: "Use i < .length instead of i <= .length in loop conditions",
			CWE:         "CWE-193",
		})
	}

	if strings.Contains(src, "i++") && strings.Contains(src, ".length") {
		checkedSub := strings.Count(src, "i <") + strings.Count(src, "i <=")
		checkedAssign := strings.Count(src, "i =") + strings.Count(src, "i++")
		if checkedSub < checkedAssign/2 {
			a.addResult(AuditResult{
				Class:       VulnOffByOne,
				Title:       "Multiple loops without length checks",
				Description: "Several increment patterns found but fewer length check patterns, suggesting some loops may lack proper bounds.",
				Severity:    SevLow,
				Confidence:  0.4,
				Remediation: "Verify all loops have correct boundary conditions with < .length",
			})
		}
	}
}

func (a *Auditor) CheckERC4626Inflation() {
	src := a.contract.Source

	isERC4626 := strings.Contains(src, "ERC4626") || strings.Contains(src, "IERC4626") || strings.Contains(src, "convertToShares") || strings.Contains(src, "convertToAssets")

	if !isERC4626 {
		return
	}

	if strings.Contains(src, "totalSupply") && strings.Contains(src, "deposit") && !strings.Contains(src, "previewDeposit") {
		a.addResult(AuditResult{
			Class:       VulnERC4626ShareInflation,
			Title:       "Missing previewDeposit in ERC-4626 vault",
			Description: "ERC-4626 vault implements deposit without previewDeposit, which may allow share inflation attacks through donation.",
			Severity:    SevHigh,
			Confidence:  0.8,
			Remediation: "Implement previewDeposit and use virtual shares/assets to prevent inflation attacks",
			SWC:         "SWC-114",
			References: []string{
				"https://blog.openzeppelin.com/root-cause-of-the-first-yield-exploit",
				"https://docs.openzeppelin.com/contracts/4.x/erc4626",
			},
		})
	}

	if strings.Contains(src, "asset") && strings.Contains(src, "totalAssets") && !strings.Contains(src, "virtual") {
		a.addResult(AuditResult{
			Class:       VulnERC4626ShareInflation,
			Title:       "Potential share inflation attack via donation",
			Description: "Vault does not use virtual shares/assets. An attacker can donate assets directly to inflate share price and steal from subsequent depositors.",
			Severity:    SevCritical,
			Confidence:  0.85,
			Remediation: "Use virtual shares and assets (offset by 10**3 or more) to prevent inflation attacks",
			SWC:         "SWC-114",
		})
	}

	if strings.Contains(src, "totalSupply") && strings.Contains(src, "totalAssets") {
		if !strings.Contains(src, "_decimalsOffset") && !strings.Contains(src, "scaled") {
			a.addResult(AuditResult{
				Class:       VulnERC4626ShareInflation,
				Title:       "Missing decimals offset for inflation defense",
				Description: "Vault uses totalSupply/totalAssets ratio without decimals offset, making it vulnerable to precision-based inflation attacks.",
				Severity:    SevMedium,
				Confidence:  0.7,
				Remediation: "Implement _decimalsOffset() or use scaled share calculation",
				SWC:         "SWC-114",
			})
		}
	}
}
