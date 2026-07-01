//! Phase 1: Proof-of-Relay settlement.
//!
//! Turns batches of verified [`RelayReceipt`]s from [`crate::relay_mining`]
//! into [`LeafEntry`] leaves that can be appended to a Solana ZK-compressed
//! Merkle tree, crediting each relay node with its earned reward.
//!
//! - [`RelaySettler::settle_batch`] is fully on-device: it validates receipts,
//!   aggregates earnings per relay, and mints one [`LeafEntry`] per relay
//!   (owner = relay pubkey, lamports = `RELAY_REWARD_LAMPORTS` × messages).
//! - [`RelaySettler::settle_to_solana`] is a Phase-1 placeholder that validates
//!   + aggregates the same way, then logs the would-be on-chain transaction.
//!   The real compressed-account write happens in Phase 2.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::leaf_store::LeafEntry;
use crate::relay_mining::{verify_two_signatures, RelayReceipt, RELAY_REWARD_LAMPORTS};

/// Per-relay aggregate for a settlement batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayEarnings {
    /// Relay node pubkey.
    pub relay: [u8; 32],
    /// Number of verified messages this relay carried in the batch.
    pub messages: u64,
    /// Lamports owed: `messages * RELAY_REWARD_LAMPORTS`.
    pub lamports: u64,
}

/// Settles batches of relay receipts into Merkle-tree leaves (Phase 1) and
/// prepares (logs) on-chain settlement (Phase 2).
pub struct RelaySettler {
    /// Next leaf index to assign within a tree (incremented per settled leaf).
    next_leaf_index: u64,
    /// Last computed earnings per relay (for UI / debugging).
    last_earnings: Vec<RelayEarnings>,
}

impl RelaySettler {
    pub fn new() -> Self {
        Self {
            next_leaf_index: 0,
            last_earnings: Vec::new(),
        }
    }

    /// Seed the leaf-index counter when appending into a tree that already has
    /// `existing_leaves` leaves.
    pub fn with_next_leaf_index(mut self, next_leaf_index: u64) -> Self {
        self.next_leaf_index = next_leaf_index;
        self
    }

    /// Last earnings computed by [`Self::settle_batch`] or
    /// [`Self::settle_to_solana`].
    pub fn last_earnings(&self) -> &[RelayEarnings] {
        &self.last_earnings
    }

    /// Aggregate a batch of receipts into per-relay earnings, dropping any
    /// receipt that fails the anti-fraud check (both signatures valid).
    pub fn aggregate(receipts: &[RelayReceipt]) -> Vec<RelayEarnings> {
        let mut totals: HashMap<[u8; 32], u64> = HashMap::new();
        for r in receipts {
            if !verify_two_signatures(r) {
                tracing::warn!(
                    relay = ?hex_short(&r.relay),
                    "Dropping invalid relay receipt during settlement"
                );
                continue;
            }
            *totals.entry(r.relay).or_insert(0) += 1;
        }
        let mut out: Vec<RelayEarnings> = totals
            .into_iter()
            .map(|(relay, messages)| RelayEarnings {
                relay,
                messages,
                lamports: messages.saturating_mul(RELAY_REWARD_LAMPORTS),
            })
            .collect();
        out.sort_by_key(|e| e.relay);
        out
    }

    /// Validate receipts, compute per-relay earnings, and mint one
    /// [`LeafEntry`] per relay node. The returned leaves are ready to be
    /// appended to the local [`crate::tree_replica::TreeReplica`] and gossip
    /// broadcast via [`crate::gossip::MeshMessage::LeafUpdate`].
    ///
    /// `merkle_tree` is the pubkey bytes of the tree the leaves belong to.
    /// `current_root` / `current_root_seq` / `current_slot` describe the tree
    /// state the new leaves are built on top of (callers should refresh these
    /// from their [`crate::tree_replica::TreeReplica`] before calling).
    pub fn settle_batch(
        &mut self,
        receipts: &[RelayReceipt],
        merkle_tree: [u8; 32],
        current_root: [u8; 32],
        current_root_seq: u64,
        current_slot: u64,
    ) -> Vec<LeafEntry> {
        let earnings = Self::aggregate(receipts);
        let mut leaves = Vec::with_capacity(earnings.len());

        for e in &earnings {
            let leaf_hash = leaf_hash_for(merkle_tree, &e.relay, e.lamports, self.next_leaf_index);
            leaves.push(LeafEntry {
                leaf_hash,
                leaf_index: self.next_leaf_index,
                merkle_tree,
                owner: e.relay,
                lamports: e.lamports,
                root: current_root,
                root_seq: current_root_seq,
                slot: current_slot,
            });
            self.next_leaf_index += 1;
        }

        self.last_earnings = earnings;
        tracing::info!(
            tree = ?hex_short(&merkle_tree),
            leaves = leaves.len(),
            "Settled relay batch into {} leaves",
            leaves.len()
        );
        leaves
    }

    /// Phase-1 placeholder for on-chain settlement.
    ///
    /// Performs the same validation + aggregation as [`Self::settle_batch`],
    /// then logs the would-be Solana transaction instead of submitting it.
    /// The real compressed-account write (via the Light Protocol / ZK
    /// Compression program) lands in Phase 2.
    pub async fn settle_to_solana(
        &mut self,
        receipts: &[RelayReceipt],
        rpc_url: &str,
        tree_pubkey: [u8; 32],
    ) -> Result<()> {
        let earnings = Self::aggregate(receipts);
        self.last_earnings = earnings.clone();

        let total_lamports: u64 = earnings.iter().map(|e| e.lamports).sum();
        let total_messages: u64 = earnings.iter().map(|e| e.messages).sum();

        tracing::info!(
            rpc = %rpc_url,
            tree = ?hex_short(&tree_pubkey),
            relays = earnings.len(),
            messages = total_messages,
            lamports = total_lamports,
            "[Phase 1 placeholder] settle_to_solana: would submit batch_append for {} relay(s), {} message(s), {} lamports",
            earnings.len(),
            total_messages,
            total_lamports
        );

        // Phase 2 will replace this log with a real RPC client call:
        //   rpc_client.send_transaction(compressed_batch_append_ix(...))
        // For now we simply report what *would* be settled.
        Ok(())
    }
}

impl Default for RelaySettler {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic leaf hash for a relay-credit leaf:
/// `SHA256(merkle_tree || owner || lamports || leaf_index)`.
///
/// This mirrors the way other EpsilonChat leaves are derived and keeps the
/// leaf content-addressable so duplicate settlement of the same receipt
/// batch produces identical (and therefore de-dupable) leaf hashes.
pub fn leaf_hash_for(
    merkle_tree: [u8; 32],
    owner: &[u8; 32],
    lamports: u64,
    leaf_index: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(merkle_tree);
    h.update(owner);
    h.update(lamports.to_le_bytes());
    h.update(leaf_index.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn hex_short(hash: &[u8; 32]) -> String {
    hex::encode(&hash[..4])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_mining::RelayMiner;
    use ed25519_dalek::SigningKey;

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret = SigningKey::from_bytes(&[seed; 32]);
        (secret.to_bytes(), secret.verifying_key().to_bytes())
    }

    fn make_receipts() -> ([u8; 32], Vec<RelayReceipt>) {
        let (relay_sk, relay_pk) = keypair(0x11);
        let (sender_sk, sender_pk) = keypair(0x22);
        let recipient = [0x33; 32];
        let ts = 1_700_000_000_000u64;

        let miner = RelayMiner::new(relay_sk);
        let mut receipts = Vec::new();
        for i in 0..3u8 {
            let r = miner.co_sign_receipt(
                miner.create_receipt(sender_pk, recipient, [i; 32], ts + i as u64),
                &sender_sk,
            );
            assert!(r.is_valid());
            receipts.push(r);
        }
        (relay_pk, receipts)
    }

    #[test]
    fn test_aggregate_drops_invalid() {
        let (relay_pk, mut receipts) = make_receipts();
        // Corrupt one receipt's signature so it fails verification.
        receipts[1].signature_relay[0] ^= 0xFF;
        assert!(!receipts[1].is_valid());

        let earnings = RelaySettler::aggregate(&receipts);
        assert_eq!(earnings.len(), 1);
        assert_eq!(earnings[0].relay, relay_pk);
        assert_eq!(earnings[0].messages, 2); // only 2 valid receipts
        assert_eq!(earnings[0].lamports, 2 * RELAY_REWARD_LAMPORTS);
    }

    #[test]
    fn test_settle_batch_produces_leaves() {
        let (relay_pk, receipts) = make_receipts();
        let tree = [0xAA; 32];
        let root = [0xBB; 32];
        let mut settler = RelaySettler::new();

        let leaves = settler.settle_batch(&receipts, tree, root, 7, 123_456);

        assert_eq!(leaves.len(), 1);
        let l = &leaves[0];
        assert_eq!(l.merkle_tree, tree);
        assert_eq!(l.owner, relay_pk);
        assert_eq!(l.lamports, 3 * RELAY_REWARD_LAMPORTS);
        assert_eq!(l.leaf_index, 0);
        assert_eq!(l.root, root);
        assert_eq!(l.root_seq, 7);
        assert_eq!(l.slot, 123_456);
        // Leaf hash is deterministic + content-addressed.
        assert_eq!(
            l.leaf_hash,
            leaf_hash_for(tree, &relay_pk, l.lamports, 0)
        );

        // Earnings accessible via last_earnings.
        assert_eq!(settler.last_earnings().len(), 1);
        assert_eq!(settler.last_earnings()[0].messages, 3);
    }

    #[test]
    fn test_settle_batch_advances_leaf_index() {
        let (_, receipts) = make_receipts();
        let tree = [0xAA; 32];
        let root = [0xBB; 32];

        // Simulate a tree that already has 5 leaves.
        let mut settler = RelaySettler::new().with_next_leaf_index(5);
        let leaves = settler.settle_batch(&receipts, tree, root, 7, 123_456);

        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].leaf_index, 5);
        // Second batch continues from where the first left off.
        let leaves2 = settler.settle_batch(&receipts, tree, root, 8, 123_457);
        assert_eq!(leaves2.len(), 1);
        assert_eq!(leaves2[0].leaf_index, 6);
    }

    #[tokio::test]
    async fn test_settle_to_solana_placeholder() {
        let (relay_pk, receipts) = make_receipts();
        let tree = [0xCC; 32];
        let mut settler = RelaySettler::new();

        let res = settler
            .settle_to_solana(&receipts, "https://api.devnet.solana.com", tree)
            .await;
        assert!(res.is_ok());

        let earnings = settler.last_earnings();
        assert_eq!(earnings.len(), 1);
        assert_eq!(earnings[0].relay, relay_pk);
        assert_eq!(earnings[0].messages, 3);
        assert_eq!(earnings[0].lamports, 3 * RELAY_REWARD_LAMPORTS);
    }

    #[test]
    fn test_empty_batch() {
        let tree = [0xDD; 32];
        let mut settler = RelaySettler::new();
        let leaves = settler.settle_batch(&[], tree, [0; 32], 0, 0);
        assert!(leaves.is_empty());
        assert!(settler.last_earnings().is_empty());
    }

    #[test]
    fn test_multiple_relays_aggregate_separately() {
        let (relay_sk_a, relay_pk_a) = keypair(0x11);
        let (relay_sk_b, relay_pk_b) = keypair(0x99);
        let (sender_sk, sender_pk) = keypair(0x22);
        let recipient = [0x33; 32];
        let ts = 1_700_000_000_000u64;

        let miner_a = RelayMiner::new(relay_sk_a);
        let miner_b = RelayMiner::new(relay_sk_b);

        let r_a = miner_a.co_sign_receipt(
            miner_a.create_receipt(sender_pk, recipient, [1; 32], ts),
            &sender_sk,
        );
        let r_b = miner_b.co_sign_receipt(
            miner_b.create_receipt(sender_pk, recipient, [2; 32], ts),
            &sender_sk,
        );
        // Two more via relay A so A earns more.
        let r_a2 = miner_a.co_sign_receipt(
            miner_a.create_receipt(sender_pk, recipient, [3; 32], ts + 1),
            &sender_sk,
        );

        let receipts = vec![r_a, r_b, r_a2];
        let earnings = RelaySettler::aggregate(&receipts);
        assert_eq!(earnings.len(), 2);

        let map: HashMap<[u8; 32], u64> = earnings.iter().map(|e| (e.relay, e.messages)).collect();
        assert_eq!(map.get(&relay_pk_a), Some(&2));
        assert_eq!(map.get(&relay_pk_b), Some(&1));
    }
}