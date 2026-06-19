# DeFi Protocol Testing Workflow

## Economic Security Testing
1. Identify protocol economic assumptions
2. Simulate flash loan price manipulation
3. Test liquidation race conditions
4. Verify arbitrage resistance
5. Stress test under extreme market conditions

## Oracle Security Testing
1. Identify oracle source (Chainlink, TWAP, custom)
2. Test TWAP manipulation resistance
3. Verify fallback oracle behavior
4. Test for stale price acceptance
5. Validate oracle deviation thresholds

## Governance Security Testing
1. Analyze voting power distribution
2. Test proposal execution timelocks
3. Verify quorum and voting period security
4. Test delegate and delegation mechanisms
5. Identify governance attack vectors
