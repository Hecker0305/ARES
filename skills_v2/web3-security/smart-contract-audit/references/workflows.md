# Smart Contract Audit Workflow

## Phase 1: Scoping
1. Review contract architecture and specifications
2. Identify critical functions and trust assumptions
3. Set up testing environment (Hardhat fork, testnet)

## Phase 2: Automated Analysis
1. Run Slither static analysis with all detectors
2. Run Mythril symbolic execution
3. Run Echidna fuzzing with property tests

## Phase 3: Manual Review
1. Reentrancy analysis (check-effects-interaction pattern)
2. Access control review (onlyOwner, roles, OpenZeppelin)
3. Arithmetic safety (overflow/underflow, rounding)
4. Oracle dependency analysis
5. Upgrade mechanism review

## Phase 4: Reporting
1. Severity classification (Critical/High/Medium/Low/Informational)
2. Proof of concept for each finding
3. Remediation recommendations with code examples
