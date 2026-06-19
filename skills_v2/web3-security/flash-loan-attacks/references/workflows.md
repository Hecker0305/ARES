# Flash Loan Attack Testing Workflow

## Attack Simulation
1. Fork mainnet at block height before known exploit
2. Deploy flash loan receiver contract
3. Execute atomic attack: borrow -> manipulate -> exploit -> repay
4. Verify profit/loss and transaction success

## Oracle Manipulation Test
1. Identify oracle price source for target protocol
2. Calculate liquidity needed to move price to exploit threshold
3. Execute flash loan swap through DEX to manipulate spot price
4. Verify protocol uses manipulated price in critical logic

## Detection Rule Development
1. Monitor for flash loan callbacks (WETH transfer + receiver call)
2. Alert on rapid price deviation within single transaction
3. Track flash loan amounts relative to pool liquidity
4. Correlate flash loans with protocol state changes
