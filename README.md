# @yeet-org/solana-registry

Public, automated Solana Verified dApps & Threat Intelligence Registry for GhostWallet and the Solana ecosystem.

## Feeds & Sources
1. **DeFiLlama Solana Index**: Protocols with active Solana TVL, verified domains, official Twitter, and security audit counts.
2. **Phantom Open-Source Blocklist**: `phantom/blocklist` community drainers & phishing domains.
3. **ScamSniffer Threat Database**: Known crypto phishing hostnames and wallet drainers.
4. **Curated Solana Ecosystem**: Top Solana-native launchpads (Pump.fun, GMGN, BullX), NFT platforms (Magic Eden, Tensor), and tooling (Solscan, SolanaFM, Dialect).

## Distribution
- **GitHub Pages CDN**: `https://yeet-org.github.io/solana-registry/verified-apps.json`
- **GitHub Raw CDN**: `https://raw.githubusercontent.com/YEET-ORG/solana-registry/main/dist/verified-apps.json`
- **Blocked Threat Domains**: `https://raw.githubusercontent.com/YEET-ORG/solana-registry/main/dist/blocked-domains.json`
- **Staking & LST Registry**: `https://raw.githubusercontent.com/YEET-ORG/solana-registry/main/dist/staking-registry.json`

## Automation
A GitHub Actions runner updates this repository every 6 hours (`.github/workflows/sync.yml`).
GhostWallet caches this data with background stale-while-revalidate, falling back to local bundled files when offline.
