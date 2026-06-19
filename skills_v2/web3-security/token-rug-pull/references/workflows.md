# Token Rug Pull Detection Workflow

## Automated Detection
1. Fetch token contract bytecode via RPC
2. Decompile with Panoramix/Dedaub
3. Check for blacklist/mint/pause functions
4. Analyze holder distribution from transfer events
5. Verify liquidity lock via locker contract calls

## Manual Investigation
1. Review deployer wallet history (previous scam deployments?)
2. Check social media presence (AI-generated content?)
3. Verify team identity and background
4. Test buy and sell transactions on testnet fork
5. Monitor for liquidity removal signals

## Red Flags to Check
- Unverified source code
- Proxy contract with upgradable implementation
- Honeypot sell restriction
- Mint function with no cap
- Blacklist/whitelist functions
- High transaction tax (>15%)
- Rugpull-liquidity not locked
- Concentrated top holder distribution
- Deployer wallet funded by exchange/mixer
