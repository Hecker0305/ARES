---
name: smart-contract-audit
description: >-
  Smart contract security audit methodology covering Solidity and Vyper contract review, vulnerability
  identification (reentrancy, access control, oracle manipulation), automated analysis tooling,
  and gas optimization verification.
domain: web3-security
subdomain: smart-contract-audit
tags: [smart-contract, solidity, audit, blockchain, reentrancy, defi, web3]
mitre_attack: [T1191, T1213, T1553, T1565]
nist_csf: [ID.RA-1, PR.PT-3, DE.CM-8, RS.AN-1]
d3fend: [D3-SA, D3-CR, D3-ACD, D3-FW]
mitre_atlas: [AML.T0001, AML.T0002, AML.T0023, AML.T0034, AML.T0042]
nist_ai_rmf: [MAP-1.1, MAP-2.1, MEASURE-1.2]
version: "1.0"
author: "ARES Team"
license: Apache-2.0
---

## When to Use

Activate this skill when conducting smart contract security audits for DeFi protocols, NFT platforms, DAO governance contracts, token contracts, and cross-chain bridge implementations.

## Prerequisites

- Solidity/Vyper compiler and development environment (Hardhat, Foundry, Truffle)
- Automated analysis tools (Slither, Mythril, Echidna, Manticore, Certora)
- Solidity experience and understanding of EVM opcodes
- Web3.js or ethers.js for contract interaction testing
- Access to contract source code and ABIs
- Testnet/mainnet fork for dynamic testing (Hardhat fork, Tenderly)
- Knowledge of common attack vectors (reentrancy, flash loans, oracle manipulation, access control)

## Workflow

1. Understand contract architecture: Review contract specifications, documentation, and data flow; identify trust assumptions and privileged roles
2. Run static analysis: Execute Slither with all detectors (reentrancy, tx.origin, timestamp dependency, uninitialized storage)
3. Run formal verification: Use Certora or Scribble to verify invariants (total supply, access control, arithmetic correctness)
4. Perform manual code review: Analyze each function for reentrancy (check-effects-interaction pattern), access control (onlyOwner, role-based), arithmetic (overflow), and logic flaws
5. Audit external dependencies: Review imported contracts (OpenZeppelin, Uniswap, Chainlink), verify version compatibility
6. Test with fuzzing: Run Echidna/Foundry fuzzing with property-based tests for edge cases and invariant violations
7. Simulate attacks: Deploy contract on mainnet fork and simulate common attacks (flash loan, sandwich, reentrancy, price manipulation)
8. Review upgrade mechanisms: Audit proxy patterns (UUPS, transparent, beacon), verify storage collision checks
9. Analyze economic incentives: Verify tokenomics alignment, check for economic attacks (voting manipulation, reward farming exploits)
10. Write audit report: Document findings with severity, proof of concept, and remediation recommendations

## Verification

- All critical/high findings are fixed or acknowledged with compensating controls
- Low/medium findings have documented risk acceptance or remediation timeline
- Test suite passes with 100% branch coverage of audited functions
- Fuzzing campaigns ran at least 50000 test cases with no invariant violations
- External dependency contracts are verified at correct versions
- Upgrade implementation preserves storage layout (no collisions)
- Deployed contract matches audited source code (verified on Etherscan)
- Gas optimizations are documented but do not introduce security risks
