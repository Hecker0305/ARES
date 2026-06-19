---
name: token-rug-pull
description: >-
  Token rug pull detection and analysis methodology covering token contract analysis, liquidity
  lock verification, honeypot detection, ownership renouncement checks, and malicious token
  deployment forensics.
domain: web3-security
subdomain: token-rug-pull
tags: [rug-pull, scam-token, honeypot, token-analysis, liquidity-check, scam-detection, web3]
mitre_attack: [T1191, T1553, T1565]
nist_csf: [ID.RA-1, DE.CM-8, RS.AN-1]
d3fend: [D3-SA, D3-CR, D3-DL, D3-FW]
mitre_atlas: [AML.T0001, AML.T0002, AML.T0005, AML.T0023]
nist_ai_rmf: [DETECT-1.1, MEASURE-1.2, MAP-1.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when analyzing suspicious token contracts for rug pull indicators, during new token launch due diligence, for token scam investigation and forensics, and when assessing DeFi project legitimacy.

## Prerequisites

- Blockchain explorer (Etherscan, BscScan, Polygonscan) access
- Solidity decompiler (Dedaub, Panoramix, Heimdall)
- Token analysis tools (Honeypot.is, RugDoc, TokenSniffer, GoPlus)
- Web3 provider for direct contract interaction (Infura, Alchemy, QuickNode)
- Python 3.10+ for automated token analysis scripts
- Liquidity lock verification tools (Unicrypt, Team Finance, DXlock)
- Understanding of ERC-20/BEP-20 standards and malicious token patterns

## Workflow

1. Analyze token contract source: Verify source code availability, check for obfuscation (bytecode-only, unverified contracts are high risk)
2. Check ownership controls: Verify owner address, check for renouncement, identify privileged functions (mint, burn, pause, blacklist, whitelist)
3. Detect honeypot mechanisms: Test buy/sell capability, check blacklist/whitelist functions, verify transfer restrictions (max tx amount, cooldown, tax)
4. Verify liquidity pool: Confirm liquidity pair creation (Uniswap, PancakeSwap), verify liquidity lock duration and locker contract
5. Analyze token distribution: Review top holder concentration, check for large pre-mine or team allocations, identify suspicious holder patterns (same deployer funding)
6. Test tax mechanisms: Evaluate buy/sell taxes, check for tax changes (variable tax, max tax override), identify fee distribution (marketing, dev, auto-LP)
7. Verify renouncement authenticity: Confirm ownership renouncement via transaction analysis, verify zero-address ownership, check for backdoor renouncement
8. Detect proxy patterns: Identify proxy contracts (transparent, UUPS) that could point to malicious implementation, verify implementation contract
9. Social engineering check: Review website, whitepaper, social media for AI-generated content, locked social accounts, fake team credentials
10. Report risk assessment: Provide rug pull risk score (critical/high/medium/low), document all red flags found, recommend investigation findings

## Verification

- Token owner cannot mint new tokens or modify contract parameters after launch
- Liquidity is locked for at least 12 months (verify lock contract and duration)
- Buy and sell functions work correctly (no honeypot restrictions)
- Top 10 holders hold less than 30% of total supply (decentralized distribution)
- Taxes are fixed and cannot exceed reasonable limits (< 15% total)
- No blacklist/whitelist functions exist that could restrict selling
- Contract is verified and readable on block explorer
- Team identities are verifiable (not anonymous or fake)
- Deployer wallet has no history of scam deployments
