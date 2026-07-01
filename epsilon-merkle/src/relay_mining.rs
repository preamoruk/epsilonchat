//! Phase 1: Crypto Mining with Proof-of-Relay.
//!
//! Relays (forester / always-online peers) earn mining rewards for forwarding
//! messages between phones. Every relayed message produces a signed
//! [`RelayReceipt`] that the relay can later settle into a Merkle tree leaf
//! via [`crate::relay_settlement`].
//!
//! Anti-fraud model:
//! - The **relay** signs first, attesting "I carried this message between
//!   `from` and `to`".
//! - The **sender** co-signs, attesting "I authored `msg_hash` and agree this
//!   relay delivered it toward `to`".
//! - A receipt is only valid (and therefore only settleable) if both
//!   signatures verify against the canonical receipt bytes and the declared
//!   participant pubkeys.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
// `Signer` trait is re-exported by ed25519_dalek and must be in scope to call
// `SigningKey::sign`.
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Reward paid per relayed message, in lamports (0.000001 SOL = 1000 lamports).
pub const RELAY_REWARD_LAMPORTS: u64 = 1_000;

/// Canonical bytes that both parties sign. Hashing the structured fields (not
/// the signatures themselves) means a receipt's signature is bound to the
/// exact `(from, to, relay, msg_hash, timestamp)` tuple it attests to.
fn canonical_receipt_bytes(
    from: &[u8; 32],
    to: &[u8; 32],
    relay: &[u8; 32],
    msg_hash: &[u8; 32],
    timestamp: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(from);
    h.update(to);
    h.update(relay);
    h.update(msg_hash);
    h.update(timestamp.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// A double-signed proof that a relay carried a message between two peers.
///
/// `signature_from`   — sender's ed25519 signature over the canonical bytes.
/// `signature_relay`  — relay's  ed25519 signature over the canonical bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayReceipt {
    /// Sender (author) pubkey.
    pub from: [u8; 32],
    /// Recipient pubkey.
    pub to: [u8; 32],
    /// Relay node pubkey (the miner earning the reward).
    pub relay: [u8; 32],
    /// Hash of the relayed chat message.
    pub msg_hash: [u8; 32],
    /// Unix-epoch milliseconds when the relay forwarded the message.
    pub timestamp: u64,
    /// Sender's signature over the canonical receipt bytes.
    pub signature_from: Vec<u8>,
    /// Relay's signature over the canonical receipt bytes.
    pub signature_relay: Vec<u8>,
}

impl RelayReceipt {
    /// Canonical digest bound to this receipt's participants + payload.
    pub fn digest(&self) -> [u8; 32] {
        canonical_receipt_bytes(&self.from, &self.to, &self.relay, &self.msg_hash, self.timestamp)
    }

    /// True iff both signatures verify against the canonical digest and the
    /// declared `from` / `relay` pubkeys. This is the single anti-fraud gate
    /// used by [`RelayMiner::verify_receipt`] and the settlement layer.
    pub fn is_valid(&self) -> bool {
        verify_two_signatures(self)
    }
}

/// Verify both signatures of a receipt against its canonical digest.
pub(crate) fn verify_two_signatures(receipt: &RelayReceipt) -> bool {
    let digest = receipt.digest();

    // Sender signature
    let sig_from = match Signature::from_slice(&receipt.signature_from) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let vk_from = match VerifyingKey::from_bytes(&receipt.from) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    if vk_from.verify_strict(&digest, &sig_from).is_err() {
        return false;
    }

    // Relay signature
    let sig_relay = match Signature::from_slice(&receipt.signature_relay) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let vk_relay = match VerifyingKey::from_bytes(&receipt.relay) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    if vk_relay.verify_strict(&digest, &sig_relay).is_err() {
        return false;
    }

    true
}

/// Stateful relay miner: creates, co-signs, verifies and batches receipts.
pub struct RelayMiner {
    /// Relay's ed25519 signing key (the miner's identity).
    relay_secret: SigningKey,
    /// Relay's pubkey bytes (cached for cheap receipt creation).
    relay_pubkey: [u8; 32],
    /// Per-peer relay counter (peer pubkey bytes → messages relayed to/from).
    relay_count: HashMap<[u8; 32], u64>,
    /// Receipts awaiting batch settlement.
    pending: Vec<RelayReceipt>,
}

impl RelayMiner {
    /// Create a new miner from the relay's 32-byte ed25519 secret key.
    pub fn new(relay_secret_bytes: [u8; 32]) -> Self {
        let relay_secret = SigningKey::from_bytes(&relay_secret_bytes);
        let relay_pubkey = relay_secret.verifying_key().to_bytes();
        Self {
            relay_secret,
            relay_pubkey,
            relay_count: HashMap::new(),
            pending: Vec::new(),
        }
    }

    /// The relay's public key (miner identity).
    pub fn relay_pubkey(&self) -> [u8; 32] {
        self.relay_pubkey
    }

    /// Create a receipt signed only by the relay. The sender must co-sign via
    /// [`RelayMiner::co_sign_receipt`] (or [`co_sign_receipt_static`]) before
    /// the receipt is considered valid.
    pub fn create_receipt(
        &self,
        from: [u8; 32],
        to: [u8; 32],
        msg_hash: [u8; 32],
        timestamp: u64,
    ) -> RelayReceipt {
        let digest = canonical_receipt_bytes(&from, &to, &self.relay_pubkey, &msg_hash, timestamp);
        let sig = self.relay_secret.sign(&digest);
        RelayReceipt {
            from,
            to,
            relay: self.relay_pubkey,
            msg_hash,
            timestamp,
            signature_from: Vec::new(),
            signature_relay: sig.to_bytes().to_vec(),
        }
    }

    /// Add the sender's co-signature to a relay-signed receipt.
    /// `sender_secret_key` is the sender's 32-byte ed25519 secret key.
    /// Returns the fully-signed receipt (not yet added to pending).
    pub fn co_sign_receipt(
        &self,
        receipt: RelayReceipt,
        sender_secret_key: &[u8; 32],
    ) -> RelayReceipt {
        let sender = SigningKey::from_bytes(sender_secret_key);
        let digest = receipt.digest();
        let sig = sender.sign(&digest);
        let mut out = receipt;
        out.signature_from = sig.to_bytes().to_vec();
        out
    }

    /// Verify a receipt's two signatures against the supplied pubkeys.
    /// `from_pubkey` is the expected sender pubkey; `relay_pubkey` is the
    /// expected relay pubkey. Both must match the receipt's declared fields
    /// **and** the signatures must verify.
    pub fn verify_receipt(
        &self,
        receipt: &RelayReceipt,
        from_pubkey: &[u8; 32],
        relay_pubkey: &[u8; 32],
    ) -> bool {
        // Field-level anti-fraud: declared participants must match the caller's
        // expectation. Prevents swapping in an attacker-controlled pubkey while
        // reusing a stolen signature.
        if receipt.from != *from_pubkey || receipt.relay != *relay_pubkey {
            return false;
        }
        verify_two_signatures(receipt)
    }

    /// Record a verified receipt as pending settlement and bump per-peer stats.
    /// Caller is responsible for verifying the receipt first (see
    /// [`RelayMiner::verify_receipt`]).
    pub fn record(&mut self, receipt: RelayReceipt) {
        *self.relay_count.entry(receipt.from).or_insert(0) += 1;
        *self.relay_count.entry(receipt.to).or_insert(0) += 1;
        self.pending.push(receipt);
    }

    /// Drain and return all pending receipts for settlement.
    pub fn batch_receipts(&mut self) -> Vec<RelayReceipt> {
        std::mem::take(&mut self.pending)
    }

    /// Total number of messages relayed (sum of per-peer counters / 2, since
    /// each relayed message touches two peers). Returns the count of recorded
    /// receipts, which is the authoritative mined-message count.
    pub fn relay_count(&self) -> u64 {
        self.pending.len() as u64
            + self.relay_count.values().map(|c| *c).sum::<u64>() / 2
    }

    /// Number of receipts currently buffered pending settlement.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Per-peer relay counts (for UI / reputation dashboards).
    pub fn per_peer_counts(&self) -> &HashMap<[u8; 32], u64> {
        &self.relay_count
    }
}

/// Free-function variant of [`RelayMiner::co_sign_receipt`] for callers that
/// hold the sender's key directly (e.g. a phone co-signing without owning a
/// `RelayMiner`).
pub fn co_sign_receipt_static(
    receipt: RelayReceipt,
    sender_secret_key: &[u8; 32],
) -> RelayReceipt {
    let sender = SigningKey::from_bytes(sender_secret_key);
    let digest = receipt.digest();
    let sig = sender.sign(&digest);
    let mut out = receipt;
    out.signature_from = sig.to_bytes().to_vec();
    out
}

/// Relay forwarding policy.
///
/// A relay should forward a message when:
///   - the message is **not** addressed to itself (`!msg_is_for_me`), and
///   - there is at least one other peer connected to carry it onward
///     (`has_other_peers`).
///
/// Returning `false` prevents wasted relays (a message destined for the relay
/// itself, or a message with nobody to forward to).
pub fn should_relay(msg_is_for_me: bool, has_other_peers: bool) -> bool {
    !msg_is_for_me && has_other_peers
}

/// Hash a chat message payload the same way the settlement layer expects,
/// so callers can produce a `msg_hash` consistent across relay + settlement.
pub fn hash_message(text: &[u8], from: &[u8; 32], timestamp: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(from);
    h.update(timestamp.to_le_bytes());
    h.update(text);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic keypair generator from a seed byte (no `rand` feature needed).
    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret = SigningKey::from_bytes(&[seed; 32]);
        let pubkey = secret.verifying_key().to_bytes();
        (secret.to_bytes(), pubkey)
    }

    #[test]
    fn test_create_and_co_sign_roundtrip() {
        let (relay_sk, relay_pk) = keypair(0x11);
        let (sender_sk, sender_pk) = keypair(0x22);
        let recipient = [0x33; 32];
        let msg_hash = [0xAB; 32];
        let ts = 1_700_000_000_000u64;

        let mut miner = RelayMiner::new(relay_sk);
        assert_eq!(miner.relay_pubkey(), relay_pk);

        // Relay signs first.
        let r = miner.create_receipt(sender_pk, recipient, msg_hash, ts);
        assert_eq!(r.relay, relay_pk);
        // Not valid until sender co-signs.
        assert!(!r.is_valid());

        // Sender co-signs.
        let r = miner.co_sign_receipt(r, &sender_sk);
        assert!(r.is_valid());

        // Full verification against caller-supplied pubkeys.
        assert!(miner.verify_receipt(&r, &sender_pk, &relay_pk));

        // Anti-fraud: wrong pubkeys must fail.
        let wrong_pk = [0xFF; 32];
        assert!(!miner.verify_receipt(&r, &wrong_pk, &relay_pk));
        assert!(!miner.verify_receipt(&r, &sender_pk, &wrong_pk));
    }

    #[test]
    fn test_tamper_detection() {
        let (relay_sk, relay_pk) = keypair(0x11);
        let (sender_sk, sender_pk) = keypair(0x22);
        let recipient = [0x33; 32];
        let msg_hash = [0xAB; 32];
        let ts = 1_700_000_000_000u64;

        let miner = RelayMiner::new(relay_sk);
        let r = miner.co_sign_receipt(
            miner.create_receipt(sender_pk, recipient, msg_hash, ts),
            &sender_sk,
        );
        assert!(r.is_valid());

        // Tamper with the recipient.
        let mut bad = r.clone();
        bad.to = [0x99; 32];
        assert!(!bad.is_valid());

        // Tamper with the msg_hash.
        let mut bad = r.clone();
        bad.msg_hash = [0x00; 32];
        assert!(!bad.is_valid());

        // Tamper with a signature byte.
        let mut bad = r.clone();
        if !bad.signature_from.is_empty() {
            bad.signature_from[0] ^= 0xFF;
        }
        assert!(!bad.is_valid());
    }

    #[test]
    fn test_batch_and_count() {
        let (relay_sk, relay_pk) = keypair(0x11);
        let (sender_sk, sender_pk) = keypair(0x22);
        let recipient = [0x33; 32];
        let ts = 1_700_000_000_000u64;

        let mut miner = RelayMiner::new(relay_sk);
        for i in 0..5u8 {
            let msg_hash = [i; 32];
            let r = miner.co_sign_receipt(
                miner.create_receipt(sender_pk, recipient, msg_hash, ts + i as u64),
                &sender_sk,
            );
            assert!(r.is_valid());
            miner.record(r);
        }
        assert_eq!(miner.pending_count(), 5);

        let batch = miner.batch_receipts();
        assert_eq!(batch.len(), 5);
        assert_eq!(miner.pending_count(), 0);

        // Each receipt bumped sender + recipient counters.
        let counts = miner.per_peer_counts();
        assert_eq!(*counts.get(&sender_pk).unwrap(), 5);
        assert_eq!(*counts.get(&recipient).unwrap(), 5);
    }

    #[test]
    fn test_should_relay_policy() {
        assert!(!should_relay(true, true));   // message is for me — don't relay
        assert!(!should_relay(false, false)); // nobody to forward to
        assert!(should_relay(false, true));   // healthy relay case
        assert!(!should_relay(true, false));
    }

    #[test]
    fn test_hash_message_stable() {
        let pk = [0x42; 32];
        let h1 = hash_message(b"hello", &pk, 123);
        let h2 = hash_message(b"hello", &pk, 123);
        assert_eq!(h1, h2);
        // Different timestamp → different hash.
        assert_ne!(h1, hash_message(b"hello", &pk, 124));
        // Different text → different hash.
        assert_ne!(h1, hash_message(b"world", &pk, 123));
    }
}