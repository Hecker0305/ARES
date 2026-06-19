---
name: defi-protocol-testing
description: >-
  DeFi protocol security testing covering liquidity pool analysis, oracle manipulation scenarios,
  MEV vulnerability assessment, governance attack vector analysis, cross-chain bridge testing,
  and economic exploit simulation.
domain: web3-security
subdomain: defi-protocol-testing
tags: [defi, liquidity-pool, oracle, mev, governance, cross-chain, protocol-testing, web3]
mitre_attack: [T1191, T1213, T1553, T1565]
nist_csf: [ID.RA-1, PR.PT-3, DE.CM-8, RS.AN-1]
d3fend: [D3-SA, D3-CR, D3-ACD, D3-FW]
mitre_atlas: [AML.T0001, AML.T0002, AML.T0023, AML.T0034, AML.T0042]
nist_ai_rmf: [MAP-1.1, MAP-2.1, MEASURE-1.2, MANAGE-2.1]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill during DeFi protocol security assessments, for liquidity pool and AMM vulnerability testing, before mainnet deployment of new DeFi protocols, and for governance attack path analysis.

## Prerequisites

- Hardhat or Foundry development environment with mainnet fork capability
- Solidity and Vyper auditing experience
- DeFi protocol understanding (AMM, lending, yield aggregator, CDP, liquidity mining)
- MEV analysis tools (Flashbots, EigenPhi, Searcher)
- Oracle manipulation testing tools (Chainlink, TWAP, custom oracle)
- Python 3.10+ for economic attack simulation
- Access to protocol source code and deployed contract addresses

## Workflow

1. Analyze protocol architecture: Document token flows, liquidity pools, and protocol interaction graph
2. Review oracle mechanism: Identify price oracle source (Chainlink, Uniswap TWAP, custom), test manipulation resistance (flash loan + swap price deviation)
3. Test AMM invariants: Verify constant product formula adherence, test for slippage manipulation, sandwich attack feasibility
4. Audit lending protocols: Test liquidation logic caps, verify collateral factors, test interest rate model edge cases
5. Assess flash loan risk: Simulate flash loan attacks against protocol (price manipulation, arbitrage, liquidation race conditions)
6. Review governance system: Analyze voting power concentration, proposal execution timelocks, quorum requirements, delegate attacks
7. Test cross-chain bridge: Verify message relay security, RPC endpoint handling, signature verification, withdrawal finality
8. Simulate MEV attacks: Test sandwich, frontrunning, and backrunning potential for high-value transactions
9. Analyze economic security: Run simulations for bank run scenarios, death spiral conditions, liquidity crises
10. Report risk assessment: Document economic attack vectors, likelihood, impact, and recommended mitigation controls

## Verification

- Oracle manipulation requires more than 30% of liquidity to move price beyond manipulation threshold
- Protocol maintains solvency under simulated stress conditions (50% deposit withdrawal, 80% price crash)
- Governance system cannot pass malicious proposals with less than 10% of token supply
- Cross-chain bridge messaging is verified with signature validation on both sides
- Flash loan resistance tested across all protocol entry points
- MEV attack cost exceeds maximum extractable value
- All invariant tests pass under 10000+ simulated market conditions
- Security assessment report covers all findings with severity ratings and remediation guidance
