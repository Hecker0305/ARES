---
name: flash-loan-attacks
description: >-
  Flash loan attack analysis and prevention methodology covering price oracle manipulation,
  arbitrage attack simulation, liquidation race attacks, governance flash loan attacks,
  and cross-protocol exploit analysis.
domain: web3-security
subdomain: flash-loan-attacks
tags: [flash-loan, defi-attack, price-manipulation, oracle-attack, arbitrage, liquidation, web3]
mitre_attack: [T1191, T1213, T1553, T1565]
nist_csf: [ID.RA-1, PR.PT-3, DE.CM-8, RS.AN-1]
d3fend: [D3-SA, D3-CR, D3-ACD, D3-FW]
mitre_atlas: [AML.T0001, AML.T0002, AML.T0023, AML.T0034, AML.T0042]
nist_ai_rmf: [MEASURE-1.2, MAP-1.1, MANAGE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when conducting flash loan attack simulations for DeFi protocol security, during oracle manipulation vulnerability assessment, for economic security analysis of lending/AMM protocols, and when developing flash loan attack detection logic.

## Prerequisites

- Hardhat or Foundry with mainnet fork capability
- Solidity experience and understanding of EVM atomic execution
- Flash loan provider integration (Aave, dYdX, Maker, Balancer)
- DeFi protocol understanding (AMM pricing, lending, liquidation)
- Python 3.10+ for economic simulation
- MEV detect tools (Flashbots, Searcher, EigenPhi)
- Mainnet RPC endpoint with archive data access

## Workflow

1. Understand flash loan mechanics: Review flash loan provider contracts (Aave LendingPool, Balancer Vault, dYdX SoloMargin), understand repayment requirements
2. Identify vulnerable protocols: Find protocols that use spot price from single DEX pair, lack TWAP, or have manipulation-susceptible oracles
3. Calculate capital requirements: Determine flash loan amount needed to manipulate target pool price to desired deviation
4. Design attack path: Construct atomic transaction (flash loan borrow -> swap manipulate price -> exploit protocol -> repay flash loan)
5. Simulate price manipulation: Use forge/brownie to simulate flash loan swap impact on target DEX pool, measure price deviation
6. Construct arbitrage attack: Create exploit that borrows flash loan, manipulates price, exploits protocol, repays with profit
7. Test liquidation race: Simulate flash loan to artificially lower collateral value and trigger liquidation, compete with liquidators
8. Analyze governance attack: Test if flash loan can temporarily acquire enough voting power to pass malicious governance proposal
9. Verify protocol defenses: Test TWAP oracle resistance, check price manipulation costs vs exploit profit, validate circuit breakers
10. Document exploit path: Write detailed PoC with Hardhat/Foundry test, including code, deployment, and execution scripts

## Verification

- Price manipulation attack requires at least 30% of pool liquidity to be profitable (minimum economic safety threshold)
- TWAP oracles resist flash loan manipulation (time-weighted pricing prevents single-block attacks)
- Lending protocol liquidation logic has minimum health factor buffer (>1.1) against flash loan manipulation
- Protocol has circuit breaker that pauses during abnormal price deviations (> 15% in single block)
- Attack simulation PoC is reproducible and produces expected results
- Protocol team acknowledged findings and applied mitigations
- Detection rules identify flash loan interactions (WETH flash loan transfers, callback patterns)
- Cost of attack exceeds maximum possible profit (economic security verified)
