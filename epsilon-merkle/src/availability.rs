//! Proof-of-Availability mining for EpsilonChat.
//!
//! Replaces the old Proof-of-Relay scheme. Foresters (always-online peers)
//! earn mining rewards by proving they are available to serve the mesh:
//!
//! - The forester periodically issues an [`AvailabilityChallenge`] containing a
//!   random nonce, targeted at a specific node (`target_node_id`).
//! - The challenged node produces an [`AvailabilityResponse`] attesting to its
//!   current mesh view: peer count and a mesh snapshot hash, signed over the
//!   challenge nonce + epoch.
//! - The forester verifies the response (nonce match + signature) and computes
//!   an [`AvailabilityCredit`] using a `uniqueness_score` — nodes that hold a
//!   unique view of the mesh earn more, discouraging Sybils that all replay the
//!   same snapshot.
//! - Credits are batch-settled into a single hash ([`AvailabilityMiner::settle_credits`])
//!   that can be appended as a Merkle tree leaf.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

/// A node identity — 32-byte ed25519 verifying key.
pub type PublicKey = [u8; 32];

/// Domain separator included in every availability signed message to avoid
/// cross-protocol signature reuse.
const AVAILABILITY_DOMAIN_TAG: &[u8] = b"epsilon-availability";

/// Base reward (in lamports) paid per verified availability response before
/// the uniqueness multiplier is applied.
pub const AVAILABILITY_BASE_REWARD_LAMPORTS: u64 = 1_000;

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A challenge issued by a forester to a target node, demanding proof that the
/// node is online and serving the mesh.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilityChallenge {
    pub epoch: u64,
    pub target_node_id: PublicKey,
    pub challenge_nonce: [u8; 32],
    pub forester_sig: Vec<u8>,
}

/// A node's signed response to an availability challenge, attesting to its
/// current mesh view.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilityResponse {
    pub epoch: u64,
    pub challenge_nonce: [u8; 32],
    pub peer_count: u32,
    pub mesh_snapshot_hash: [u8; 32],
    pub responder_sig: Vec<u8>,
}

/// A credit awarded to a node for a verified availability response. Aggregated
/// into a batch and settled to a Merkle leaf by [`AvailabilityMiner::settle_credits`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilityCredit {
    pub node_id: PublicKey,
    pub epoch: u64,
    pub credit_amount: u64,
    pub stake_amount: u64,
    pub uniqueness_score: f64,
    pub forester_sig: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read 32 cryptographically random bytes from the OS CSPRNG.
fn read_random_bytes_32() -> [u8; 32] {
    if let Ok(mut f) = File::open("/dev/urandom") {
        let mut buf = [0u8; 32];
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    // Insecure fallback (only if /dev/urandom is unavailable).
    let mut hasher = Sha256::new();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.update(ts.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Canonical message bytes that the forester signs when issuing a challenge.
fn challenge_signed_message(epoch: u64, target: &PublicKey, nonce: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 32 + 32 + AVAILABILITY_DOMAIN_TAG.len());
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(target);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(AVAILABILITY_DOMAIN_TAG);
    msg
}

/// Canonical message bytes that the responder signs when responding.
fn response_signed_message(
    epoch: u64,
    nonce: &[u8; 32],
    peer_count: u32,
    mesh_hash: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 32 + 4 + 32 + AVAILABILITY_DOMAIN_TAG.len());
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(&peer_count.to_le_bytes());
    msg.extend_from_slice(mesh_hash);
    msg.extend_from_slice(AVAILABILITY_DOMAIN_TAG);
    msg
}

/// Canonical message bytes that the forester signs when issuing a credit.
fn credit_signed_message(
    node_id: &PublicKey,
    epoch: u64,
    credit_amount: u64,
    stake_amount: u64,
    uniqueness: f64,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(node_id);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&credit_amount.to_le_bytes());
    msg.extend_from_slice(&stake_amount.to_le_bytes());
    msg.extend_from_slice(&uniqueness.to_le_bytes());
    msg.extend_from_slice(AVAILABILITY_DOMAIN_TAG);
    msg
}

/// Verify an ed25519 signature over `message` against `pubkey`. Returns
/// `false` on any parse or verification failure.
fn verify_sig(pubkey: &PublicKey, message: &[u8], sig_bytes: &[u8]) -> bool {
    let vk = match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(message, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// AvailabilityMiner (forester side)
// ---------------------------------------------------------------------------

/// A forester that issues availability challenges, verifies responses, and
/// settles credits into Merkle leaves.
pub struct AvailabilityMiner {
    forester_secret: SigningKey,
    forester_pubkey: PublicKey,
}

impl AvailabilityMiner {
    /// Create a new miner from the forester's 32-byte ed25519 secret key.
    pub fn new(forester_secret_bytes: [u8; 32]) -> Self {
        let forester_secret = SigningKey::from_bytes(&forester_secret_bytes);
        let forester_pubkey = forester_secret.verifying_key().to_bytes();
        Self {
            forester_secret,
            forester_pubkey,
        }
    }

    /// The forester's public key (miner identity).
    pub fn forester_pubkey(&self) -> PublicKey {
        self.forester_pubkey
    }

    /// Issue a fresh availability challenge to `target` for the given `epoch`.
    /// Generates a random nonce and signs it with the forester's key.
    pub fn issue_challenge(&self, target: PublicKey, epoch: u64) -> AvailabilityChallenge {
        let challenge_nonce = read_random_bytes_32();
        let msg = challenge_signed_message(epoch, &target, &challenge_nonce);
        let sig = self.forester_secret.sign(&msg);
        AvailabilityChallenge {
            epoch,
            target_node_id: target,
            challenge_nonce,
            forester_sig: sig.to_bytes().to_vec(),
        }
    }

    /// Verify a challenge's forester signature is well-formed (utility used
    /// by responders to ensure the challenge is authentic before responding).
    pub fn verify_challenge_sig(&self, challenge: &AvailabilityChallenge) -> bool {
        let msg = challenge_signed_message(
            challenge.epoch,
            &challenge.target_node_id,
            &challenge.challenge_nonce,
        );
        verify_sig(&self.forester_pubkey, &msg, &challenge.forester_sig)
    }

    /// Verify a response against a challenge.
    ///
    /// Checks that:
    /// - the nonce matches the challenge nonce,
    /// - the epoch matches the challenge epoch,
    /// - the responder's signature is valid over the canonical response message.
    ///
    /// `responder_pubkey` is the expected public key of the responding node
    /// (must match `challenge.target_node_id` for a legitimate round trip).
    pub fn verify_response(
        &self,
        challenge: &AvailabilityChallenge,
        response: &AvailabilityResponse,
    ) -> bool {
        // Nonce must match.
        if response.challenge_nonce != challenge.challenge_nonce {
            return false;
        }
        // Epoch must match.
        if response.epoch != challenge.epoch {
            return false;
        }
        // The responder is expected to be the challenged node.
        let responder_pubkey = challenge.target_node_id;
        let msg = response_signed_message(
            response.epoch,
            &response.challenge_nonce,
            response.peer_count,
            &response.mesh_snapshot_hash,
        );
        verify_sig(&responder_pubkey, &msg, &response.responder_sig)
    }

    /// Calculate the credit owed for a verified response.
    ///
    /// `credit = AVAILABILITY_BASE_REWARD_LAMPORTS * uniqueness_score`,
    /// floored to an integer and clamped to a minimum of 0. The `stake` and
    /// `uniqueness` parameters are recorded on the resulting credit for
    /// downstream auditing / anti-Sybil scoring; only `uniqueness` scales the
    /// reward in this base implementation.
    pub fn calculate_credit(
        &self,
        _response: &AvailabilityResponse,
        stake: u64,
        uniqueness: f64,
    ) -> u64 {
        let raw = AVAILABILITY_BASE_REWARD_LAMPORTS as f64 * uniqueness;
        if raw <= 0.0 || uniqueness.is_nan() {
            return 0;
        }
        let credit = raw.floor() as u64;
        // stake does not scale the reward directly in the base model, but it is
        // recorded on the credit for auditability.
        let _ = stake;
        credit
    }

    /// Issue a signed [`AvailabilityCredit`] for a verified response.
    ///
    /// Convenience wrapper: computes the credit amount, signs the credit with
    /// the forester key, and returns the full credit struct.
    pub fn issue_credit(
        &self,
        response: &AvailabilityResponse,
        node_id: PublicKey,
        stake: u64,
        uniqueness: f64,
    ) -> AvailabilityCredit {
        let credit_amount = self.calculate_credit(response, stake, uniqueness);
        let msg = credit_signed_message(&node_id, response.epoch, credit_amount, stake, uniqueness);
        let sig = self.forester_secret.sign(&msg);
        AvailabilityCredit {
            node_id,
            epoch: response.epoch,
            credit_amount,
            stake_amount: stake,
            uniqueness_score: uniqueness,
            forester_sig: sig.to_bytes().to_vec(),
        }
    }

    /// Settle a batch of credits into a single hash suitable for use as a
    /// Merkle tree leaf. The hash is `SHA256(domain || node_id || epoch ||
    /// credit_amount || stake || uniqueness || forester_sig)` for each credit,
    /// folded together in order.
    pub fn settle_credits(&self, credits: Vec<AvailabilityCredit>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"epsilon-availability-settle");
        for c in &credits {
            hasher.update(c.node_id);
            hasher.update(c.epoch.to_le_bytes());
            hasher.update(c.credit_amount.to_le_bytes());
            hasher.update(c.stake_amount.to_le_bytes());
            hasher.update(c.uniqueness_score.to_le_bytes());
            hasher.update(&c.forester_sig);
        }
        let digest = hasher.finalize();
        digest.to_vec()
    }

    /// Verify a credit's forester signature.
    pub fn verify_credit_sig(&self, credit: &AvailabilityCredit) -> bool {
        let msg = credit_signed_message(
            &credit.node_id,
            credit.epoch,
            credit.credit_amount,
            credit.stake_amount,
            credit.uniqueness_score,
        );
        verify_sig(&self.forester_pubkey, &msg, &credit.forester_sig)
    }
}

// ---------------------------------------------------------------------------
// AvailabilityResponder (node side)
// ---------------------------------------------------------------------------

/// A node that responds to availability challenges from foresters.
pub struct AvailabilityResponder {
    my_secret: SigningKey,
    my_pubkey: PublicKey,
}

impl AvailabilityResponder {
    /// Create a new responder from the node's 32-byte ed25519 secret key.
    pub fn new(my_secret_bytes: [u8; 32]) -> Self {
        let my_secret = SigningKey::from_bytes(&my_secret_bytes);
        let my_pubkey = my_secret.verifying_key().to_bytes();
        Self {
            my_secret,
            my_pubkey,
        }
    }

    /// The node's public key.
    pub fn my_pubkey(&self) -> PublicKey {
        self.my_pubkey
    }

    /// Produce a signed response to a challenge.
    ///
    /// `peer_count` is the number of mesh peers currently connected, and
    /// `mesh_hash` is a hash of the node's current mesh snapshot. The
    /// response is signed over `(epoch || nonce || peer_count || mesh_hash)`.
    pub fn respond(
        &self,
        challenge: &AvailabilityChallenge,
        peer_count: u32,
        mesh_hash: [u8; 32],
    ) -> AvailabilityResponse {
        let msg = response_signed_message(
            challenge.epoch,
            &challenge.challenge_nonce,
            peer_count,
            &mesh_hash,
        );
        let sig = self.my_secret.sign(&msg);
        AvailabilityResponse {
            epoch: challenge.epoch,
            challenge_nonce: challenge.challenge_nonce,
            peer_count,
            mesh_snapshot_hash: mesh_hash,
            responder_sig: sig.to_bytes().to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Epoch system
// ---------------------------------------------------------------------------

/// Configuration for the availability epoch clock.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Duration of one epoch in seconds.
    pub duration_secs: u64,
    /// The current epoch number.
    pub current_epoch: u64,
    /// Unix timestamp (seconds) at which the current epoch started.
    pub epoch_start_ts: u64,
    /// The timestamp of the last challenge issued (seconds). Used by
    /// [`EpochConfig::is_challenge_due`] to throttle challenges.
    pub last_challenge_ts: u64,
}

impl EpochConfig {
    pub fn new(duration_secs: u64, current_epoch: u64, epoch_start_ts: u64) -> Self {
        Self {
            duration_secs,
            current_epoch,
            epoch_start_ts,
            last_challenge_ts: 0,
        }
    }

    /// Advance the epoch by one, resetting the start timestamp to
    /// `epoch_start_ts + duration_secs`.
    pub fn advance_epoch(&mut self) -> u64 {
        self.current_epoch = self.current_epoch.saturating_add(1);
        self.epoch_start_ts = self.epoch_start_ts.saturating_add(self.duration_secs);
        self.current_epoch
    }

    /// True if a new challenge is due. A challenge is due when the elapsed time
    /// since `last_challenge_ts` is at least `min_interval_secs`.
    pub fn is_challenge_due(&self, now_ts: u64, min_interval_secs: u64) -> bool {
        now_ts.saturating_sub(self.last_challenge_ts) >= min_interval_secs
    }

    /// Record that a challenge was issued at `ts`.
    pub fn record_challenge(&mut self, ts: u64) {
        self.last_challenge_ts = ts;
    }

    /// True if `now_ts` has passed the end of the current epoch.
    pub fn is_epoch_elapsed(&self, now_ts: u64) -> bool {
        now_ts.saturating_sub(self.epoch_start_ts) >= self.duration_secs
    }
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self::new(3600, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic keypair from a single seed byte (no `rand` feature needed).
    fn keypair(seed: u8) -> ([u8; 32], PublicKey) {
        let secret = SigningKey::from_bytes(&[seed; 32]);
        (secret.to_bytes(), secret.verifying_key().to_bytes())
    }

    // 1. challenge creation and verification
    #[test]
    fn test_challenge_creation_and_verification() {
        let (forester_sk, forester_pk) = keypair(0x01);
        let (node_sk, node_pk) = keypair(0x02);
        let miner = AvailabilityMiner::new(forester_sk);
        assert_eq!(miner.forester_pubkey(), forester_pk);

        let challenge = miner.issue_challenge(node_pk, 7);
        assert_eq!(challenge.epoch, 7);
        assert_eq!(challenge.target_node_id, node_pk);
        // nonce should be non-zero (overwhelmingly likely)
        assert_ne!(challenge.challenge_nonce, [0u8; 32]);
        // forester signature should verify
        assert!(miner.verify_challenge_sig(&challenge));
    }

    // 2. response signing and verification
    #[test]
    fn test_response_signing_and_verification() {
        let (forester_sk, _) = keypair(0x01);
        let (node_sk, node_pk) = keypair(0x02);

        let miner = AvailabilityMiner::new(forester_sk);
        let responder = AvailabilityResponder::new(node_sk);

        let challenge = miner.issue_challenge(node_pk, 3);
        let mesh_hash = [0xAA; 32];
        let response = responder.respond(&challenge, 42, mesh_hash);

        assert!(miner.verify_response(&challenge, &response));
        assert_eq!(response.peer_count, 42);
        assert_eq!(response.mesh_snapshot_hash, mesh_hash);
    }

    // 3. nonce mismatch detection
    #[test]
    fn test_nonce_mismatch_detected() {
        let (forester_sk, _) = keypair(0x01);
        let (node_sk, node_pk) = keypair(0x02);

        let miner = AvailabilityMiner::new(forester_sk);
        let responder = AvailabilityResponder::new(node_sk);

        let challenge = miner.issue_challenge(node_pk, 3);
        let mut response = responder.respond(&challenge, 10, [0xBB; 32]);
        // tamper the nonce
        response.challenge_nonce[0] ^= 0xFF;
        assert!(!miner.verify_response(&challenge, &response));
    }

    // 4. invalid signature rejection
    #[test]
    fn test_invalid_signature_rejected() {
        let (forester_sk, _) = keypair(0x01);
        let (node_sk, node_pk) = keypair(0x02);

        let miner = AvailabilityMiner::new(forester_sk);
        let responder = AvailabilityResponder::new(node_sk);

        let challenge = miner.issue_challenge(node_pk, 3);
        let mut response = responder.respond(&challenge, 10, [0xBB; 32]);
        // corrupt the signature
        response.responder_sig[0] ^= 0xFF;
        assert!(!miner.verify_response(&challenge, &response));
    }

    // 5. credit calculation with different uniqueness scores
    #[test]
    fn test_credit_calculation_different_uniqueness() {
        let (forester_sk, _) = keypair(0x01);
        let (node_sk, node_pk) = keypair(0x02);

        let miner = AvailabilityMiner::new(forester_sk);
        let responder = AvailabilityResponder::new(node_sk);
        let challenge = miner.issue_challenge(node_pk, 1);
        let response = responder.respond(&challenge, 5, [0x11; 32]);

        let full = miner.calculate_credit(&response, 1_000, 1.0);
        let half = miner.calculate_credit(&response, 1_000, 0.5);
        let quarter = miner.calculate_credit(&response, 1_000, 0.25);

        assert_eq!(full, AVAILABILITY_BASE_REWARD_LAMPORTS);
        assert_eq!(half, AVAILABILITY_BASE_REWARD_LAMPORTS / 2);
        assert_eq!(quarter, AVAILABILITY_BASE_REWARD_LAMPORTS / 4);
        // ordering: full > half > quarter
        assert!(full > half);
        assert!(half > quarter);
    }

    // 6. credit calculation with zero stake
    #[test]
    fn test_credit_calculation_zero_stake() {
        let (forester_sk, _) = keypair(0x01);
        let (node_sk, node_pk) = keypair(0x02);

        let miner = AvailabilityMiner::new(forester_sk);
        let responder = AvailabilityResponder::new(node_sk);
        let challenge = miner.issue_challenge(node_pk, 1);
        let response = responder.respond(&challenge, 5, [0x11; 32]);

        // zero stake still earns a credit (stake does not gate the reward).
        let credit = miner.calculate_credit(&response, 0, 1.0);
        assert_eq!(credit, AVAILABILITY_BASE_REWARD_LAMPORTS);

        // negative-equivalent uniqueness yields 0.
        let credit_neg = miner.calculate_credit(&response, 1_000, -1.0);
        assert_eq!(credit_neg, 0);

        // NaN uniqueness yields 0.
        let credit_nan = miner.calculate_credit(&response, 1_000, f64::NAN);
        assert_eq!(credit_nan, 0);
    }

    // 7. batch settlement hashing
    #[test]
    fn test_batch_settlement_hashing() {
        let (forester_sk, _) = keypair(0x01);
        let (node_sk, node_pk) = keypair(0x02);
        let (node2_sk, node2_pk) = keypair(0x03);

        let miner = AvailabilityMiner::new(forester_sk);
        let responder = AvailabilityResponder::new(node_sk);
        let responder2 = AvailabilityResponder::new(node2_sk);

        let c1 = miner.issue_challenge(node_pk, 5);
        let r1 = responder.respond(&c1, 3, [0x01; 32]);
        let credit1 = miner.issue_credit(&r1, node_pk, 500, 1.0);

        let c2 = miner.issue_challenge(node2_pk, 5);
        let r2 = responder2.respond(&c2, 7, [0x02; 32]);
        let credit2 = miner.issue_credit(&r2, node2_pk, 200, 0.5);

        // both credits should verify against the forester pubkey.
        assert!(miner.verify_credit_sig(&credit1));
        assert!(miner.verify_credit_sig(&credit2));

        let hash_a = miner.settle_credits(vec![credit1.clone(), credit2.clone()]);
        let hash_b = miner.settle_credits(vec![credit1.clone(), credit2.clone()]);
        assert_eq!(hash_a, hash_b);
        assert_eq!(hash_a.len(), 32);

        // different set of credits -> different hash
        let hash_c = miner.settle_credits(vec![credit2.clone()]);
        assert_ne!(hash_a, hash_c);

        // empty batch still produces a stable 32-byte hash
        let empty = miner.settle_credits(vec![]);
        assert_eq!(empty.len(), 32);
        let empty2 = miner.settle_credits(vec![]);
        assert_eq!(empty, empty2);
    }

    // 8. epoch advancement
    #[test]
    fn test_epoch_advancement() {
        let mut cfg = EpochConfig::new(3600, 0, 1_000_000);
        assert_eq!(cfg.current_epoch, 0);
        assert_eq!(cfg.epoch_start_ts, 1_000_000);

        let next = cfg.advance_epoch();
        assert_eq!(next, 1);
        assert_eq!(cfg.current_epoch, 1);
        assert_eq!(cfg.epoch_start_ts, 1_003_600);

        let next2 = cfg.advance_epoch();
        assert_eq!(next2, 2);
        assert_eq!(cfg.epoch_start_ts, 1_007_200);
    }

    // 9. challenge due timing
    #[test]
    fn test_challenge_due_timing() {
        let mut cfg = EpochConfig::new(3600, 0, 1_000_000);
        // no challenge issued yet -> due immediately (0 - 0 >= any positive? no,
        // 0 - 0 = 0 which is < min_interval for min>0; use a sensible min)
        assert!(!cfg.is_challenge_due(0, 10));
        assert!(cfg.is_challenge_due(10, 10));

        cfg.record_challenge(100);
        assert!(!cfg.is_challenge_due(109, 10));
        assert!(cfg.is_challenge_due(110, 10));
        assert!(cfg.is_challenge_due(200, 10));

        // zero min interval: always due
        cfg.record_challenge(100);
        assert!(cfg.is_challenge_due(100, 0));
    }

    // 10. response from wrong node rejected
    #[test]
    fn test_response_from_wrong_node_rejected() {
        let (forester_sk, _) = keypair(0x01);
        let (node_sk, node_pk) = keypair(0x02);
        let (other_sk, other_pk) = keypair(0x03);

        let miner = AvailabilityMiner::new(forester_sk);
        let responder = AvailabilityResponder::new(node_sk);
        let impostor = AvailabilityResponder::new(other_sk);

        // challenge is targeted at node_pk, but the impostor (other_pk)
        // responds with its own key.
        let challenge = miner.issue_challenge(node_pk, 9);
        let impostor_response = impostor.respond(&challenge, 99, [0xCC; 32]);

        // verify_response uses challenge.target_node_id as the expected
        // responder pubkey, so the impostor's signature must fail.
        assert!(!miner.verify_response(&challenge, &impostor_response));

        // the legitimate node's response verifies.
        let legit_response = responder.respond(&challenge, 12, [0xDD; 32]);
        assert!(miner.verify_response(&challenge, &legit_response));

        // sanity: the impostor's pubkey differs from the target
        assert_ne!(other_pk, node_pk);
    }

    // extra: epoch mismatch rejection
    #[test]
    fn test_epoch_mismatch_rejected() {
        let (forester_sk, _) = keypair(0x01);
        let (node_sk, node_pk) = keypair(0x02);

        let miner = AvailabilityMiner::new(forester_sk);
        let responder = AvailabilityResponder::new(node_sk);

        let challenge = miner.issue_challenge(node_pk, 5);
        let mut response = responder.respond(&challenge, 8, [0xEE; 32]);
        // bump epoch in the response
        response.epoch = 999;
        assert!(!miner.verify_response(&challenge, &response));
    }

    // extra: credit signature verification round-trip
    #[test]
    fn test_credit_signature_roundtrip() {
        let (forester_sk, forester_pk) = keypair(0x01);
        let (node_sk, node_pk) = keypair(0x02);

        let miner = AvailabilityMiner::new(forester_sk);
        let responder = AvailabilityResponder::new(node_sk);
        let challenge = miner.issue_challenge(node_pk, 4);
        let response = responder.respond(&challenge, 6, [0x22; 32]);
        let credit = miner.issue_credit(&response, node_pk, 777, 0.75);

        assert_eq!(credit.node_id, node_pk);
        assert_eq!(credit.epoch, 4);
        assert_eq!(credit.stake_amount, 777);
        assert_eq!(
            credit.credit_amount,
            (AVAILABILITY_BASE_REWARD_LAMPORTS as f64 * 0.75).floor() as u64
        );
        assert!(miner.verify_credit_sig(&credit));

        // tamper the credit amount -> signature fails
        let mut bad = credit.clone();
        bad.credit_amount += 1;
        assert!(!miner.verify_credit_sig(&bad));

        // forester pubkey recorded
        assert_eq!(miner.forester_pubkey(), forester_pk);
    }

    // extra: is_epoch_elapsed
    #[test]
    fn test_is_epoch_elapsed() {
        let cfg = EpochConfig::new(3600, 0, 1_000_000);
        assert!(!cfg.is_epoch_elapsed(1_000_000));
        assert!(!cfg.is_epoch_elapsed(1_003_599));
        assert!(cfg.is_epoch_elapsed(1_003_600));
        assert!(cfg.is_epoch_elapsed(1_004_000));
    }
}
