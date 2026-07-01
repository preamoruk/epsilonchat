# EpsilonChat

Pure P2P mesh messenger forked from Delta Chat. No servers, no email, no VPS. Phones connect directly via Iroh mesh. Token (EPS) earned by being online (Proof-of-Availability), spent as P2P payments inside chat.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Delta Chat Android App              │
│    (real chat UI — cloned from deltachat-android) │
│    message bubbles, contacts, groups, files       │
├─────────────────────────────────────────────────┤
│           EpsilonChat modifications               │
│  • Replace IMAP/SMTP → Iroh mesh transport        │
│  • Add EPS payments in chat (attach tokens)       │
│  • Add availability mining status in UI           │
├─────────────────────────────────────────────────┤
│            Rust Core (deltachat-core + epsilon)    │
│                                                    │
│  ┌──────────┐ ┌───────────┐ ┌──────────────────┐ │
│  │ Delta    │ │ Iroh Mesh │ │ Merkle Tree      │ │
│  │ Chat Core│ │ Transport │ │ (ZK Compressed)  │ │
│  │ (chat,   │ │ (P2P, no  │ │ (off-chain       │ │
│  │ contacts,│ │  servers) │ │  replica+proofs) │ │
│  │ groups)  │ │           │ │                  │ │
│  └──────────┘ └───────────┘ └──────────────────┘ │
│                                                    │
│  ┌────────────────┐ ┌───────────────────────────┐ │
│  │ Availability   │ │ SPL Token (EPS)           │ │
│  │ Mining         │ │ • P2P payments in chat    │ │
│  │ • Challenge/   │ │ • Balance, transfer, mint │ │
│  │   response     │ │ • Stake to earn           │ │
│  │ • Earn EPS     │ │ • Topological uniqueness  │ │
│  └────────────────┘ └───────────────────────────┘ │
│                                                    │
│  ┌────────────────┐ ┌───────────────────────────┐ │
│  │ VRF Sortition  │ │ Fraud Detection           │ │
│  • Random         │ │ • Forester accountability │ │
│    validator      │ │ • Cluster/farm detection  │ │
│    election       │ │ • Slashing                │ │
│  └────────────────┘ └───────────────────────────┘ │
├─────────────────────────────────────────────────┤
│              Solana (ZK Compression)               │
│   Merkle root on-chain, leaves off-chain           │
│   ~$0.00075/tx, batch settlements                  │
└─────────────────────────────────────────────────┘
```

## Key Differences from Delta Chat

| Feature | Delta Chat | EpsilonChat |
|---|---|---|
| Transport | IMAP/SMTP (email servers) | Iroh P2P mesh (no servers) |
| Bootstrap | Email address + password | Invite link / QR code |
| Anti-spam | Email server rate limits | Contact model + rate limiting |
| Token | None | EPS (Solana SPL, ZK-compressed) |
| Mining | None | Proof-of-Availability (be online = earn) |
| Payments | None | P2P EPS transfers inside chat |
| Validators | N/A | VRF-elected foresters, fraud slashing |
| Sybil resistance | N/A | Stake-to-earn + topological uniqueness |

## Tokenomics

- **Token:** EPS (SPL on Solana, ZK-compressed)
- **Earning:** Proof-of-Availability — phone responds to random challenges from forester
- **Spending:** P2P payments to contacts inside chat (like WeChat Pay, but P2P)
- **Anti-farm:** Stake-to-earn (must buy EPS first) + topological uniqueness (co-located phones earn less) + cluster slashing
- **Anti-spam:** Contact model + rate limiting (no token fee per message)

## Building

```bash
# Rust core
cd epsilon-merkle
cargo build
cargo test  # 65 tests

# Web UI (macOS)
cargo run -- web --port 8848
# Opens http://localhost:8848

# Android APK
cd Android/gradle-project
./gradlew assembleRelease
# Output: app/build/outputs/apk/release/app-release.apk
```

## License

GPL-3.0 (inherited from Delta Chat core)