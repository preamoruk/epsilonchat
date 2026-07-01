# EpsilonChat — Mesh-Stored Merkle Tree

Standalone crate for testing mesh-distributed Merkle tree storage
for Solana ZK Compression. Replaces centralized indexer (Helius DAS)
with P2P distribution via Iroh gossip.

## Build

```bash
cd epsilon-merkle
cargo build
```

## Run Tests

```bash
cargo test
```

## Manual Testing (2 terminals on one machine)

### Terminal 1: Generate invite link

```bash
cargo run -- invite
```

Output:
```
=== EpsilonChat Invite Link ===
{"id":"...","addrs":[]}
================================
```

Copy the JSON string.

### Terminal 2: Connect via invite

```bash
cargo run -- connect '{"id":"...","addrs":[]}'
```

### Terminal 1: Run as forester (desktop — stores all leaves)

```bash
cargo run -- forester --tree 11111111111111111111111111111111
```

### Terminal 2: Run as phone (stores only own leaves)

```bash
cargo run -- phone --owner 11111111111111111111111111111111
```

## Architecture

```
Forester (desktop)              Phone
┌─────────────────┐             ┌─────────────────┐
│  Solana devnet   │             │  Own leaf only   │
│  RPC polling     │             │  (100 bytes)     │
│       ↓         │             │                  │
│  LeafStore      │  Iroh       │  LeafStore       │
│  (all leaves)   │  gossip     │  (filtered)      │
│       ↓         │ ←────────→  │       ↓          │
│  TreeReplica    │  broadcast  │  Balance display  │
│  (full tree)    │             │                  │
│       ↓         │  Iroh DHT    │       ↓          │
│  ProofProvider   │ ←────────→  │  ProofRequester  │
│  (serves proofs) │             │  (asks proofs)   │
└─────────────────┘             └─────────────────┘
```

## Modules

| Module | Purpose |
|--------|---------|
| `leaf_store.rs` | Local leaf storage (full for forester, filtered for phone) |
| `tree_replica.rs` | Off-chain Merkle tree with proof generation/verification |
| `mesh_indexer.rs` | Listens to Solana RPC, extracts leaves, updates tree |
| `proof_provider.rs` | Serves Merkle proofs to phone peers |
| `proof_requester.rs` | Phone-side: requests proofs from forester |
| `gossip.rs` | Iroh gossip protocol, invite links, peer connection |
| `main.rs` | CLI entry point (forester / phone / invite / connect) |