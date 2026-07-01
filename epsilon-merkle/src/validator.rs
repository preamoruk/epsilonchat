//! Validator logic for EpsilonChat.
//!
//! Phone validators are elected via VRF sortition (see `vrf_sortition`).
//! Each validator independently checks the Merkle root broadcast by the
//! forester against the on-chain root. On mismatch, a validator constructs
//! and signs a fraud proof that can be submitted on-chain.

use anyhow::Result;
use ed25519_dalek::{Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A validator node: holds an identity, VRF key pair, and election state.
#[derive(Clone, Debug)]
pub struct Validator {
    /// Iroh endpoint ID of this validator.
    pub node_id: String,
    /// VRF / signing key pair used for sortition and signing fraud proofs.
    pub vrf_keypair: crate::vrf_sortition::VrfKeyPair,
    /// Current epoch number.
    pub epoch: u64,
    /// Whether this validator was elected for the current epoch.
    pub elected: bool,
}

impl Validator {
    /// Create a new validator with a freshly generated VRF key pair.
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            vrf_keypair: crate::vrf_sortition::VrfKeyPair::generate(),
            epoch: 0,
            elected: false,
        }
    }

    /// Create a validator from an existing secret seed.
    pub fn from_secret(node_id: String, secret: [u8; 32]) -> Self {
        Self {
            node_id,
            vrf_keypair: crate::vrf_sortition::VrfKeyPair::from_secret(secret),
            epoch: 0,
            elected: false,
        }
    }
}

/// Result of comparing a broadcasted root against the on-chain root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RootCheckResult {
    /// The broadcasted root matches the on-chain root.
    Valid,
    /// The roots differ.
    Invalid { expected: [u8; 32], got: [u8; 32] },
}

/// A signed fraud proof proving the forester broadcast an incorrect root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudProof {
    /// Iroh endpoint ID of the validator producing this proof.
    pub validator_node_id: String,
    /// The correct on-chain root.
    pub expected_root: [u8; 32],
    /// The incorrect root that was broadcast.
    pub actual_root: [u8; 32],
    /// Index of the leaf that fails inclusion (or is missing).
    pub leaf_index: u64,
    /// Hash of the leaf in question.
    pub leaf_hash: [u8; 32],
    /// Merkle inclusion proof (sibling hashes from leaf to root).
    pub merkle_proof: Vec<[u8; 32]>,
    /// Unix timestamp (seconds) when the proof was generated.
    pub timestamp: u64,
    /// Ed25519 signature over the canonical encoding of the proof fields
    /// (excluding the signature itself).
    pub signature: Vec<u8>,
}

/// Validator operations: root checking, fraud proof generation, and submission.
pub struct ValidatorLogic;

impl ValidatorLogic {
    /// Compare a root broadcast by the forester with the authoritative on-chain root.
    pub fn check_root(broadcasted_root: [u8; 32], on_chain_root: [u8; 32]) -> RootCheckResult {
        if broadcasted_root == on_chain_root {
            RootCheckResult::Valid
        } else {
            RootCheckResult::Invalid {
                expected: on_chain_root,
                got: broadcasted_root,
            }
        }
    }

    /// Build the canonical message that gets signed for a fraud proof.
    ///
    /// The message is the concatenation of all proof fields except the
    /// signature, in field order, with fixed-size arrays raw-encoded.
    fn fraud_proof_signing_message(
        validator_node_id: &str,
        expected_root: &[u8; 32],
        actual_root: &[u8; 32],
        leaf_index: u64,
        leaf_hash: &[u8; 32],
        merkle_proof: &[[u8; 32]],
        timestamp: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(validator_node_id.as_bytes());
        msg.extend_from_slice(expected_root);
        msg.extend_from_slice(actual_root);
        msg.extend_from_slice(&leaf_index.to_le_bytes());
        msg.extend_from_slice(leaf_hash);
        for sibling in merkle_proof {
            msg.extend_from_slice(sibling);
        }
        msg.extend_from_slice(&timestamp.to_le_bytes());
        msg
    }

    /// Generate a signed fraud proof for a root mismatch.
    ///
    /// `validator` provides the signing key and node ID. The remaining
    /// arguments describe the specific leaf that fails inclusion.
    pub fn generate_fraud_proof(
        validator: &Validator,
        expected_root: [u8; 32],
        actual_root: [u8; 32],
        leaf_index: u64,
        leaf_hash: [u8; 32],
        merkle_proof: Vec<[u8; 32]>,
    ) -> FraudProof {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let msg = Self::fraud_proof_signing_message(
            &validator.node_id,
            &expected_root,
            &actual_root,
            leaf_index,
            &leaf_hash,
            &merkle_proof,
            timestamp,
        );

        let signature = validator.vrf_keypair.secret.sign(&msg);
        let sig_bytes = signature.to_bytes();

        FraudProof {
            validator_node_id: validator.node_id.clone(),
            expected_root,
            actual_root,
            leaf_index,
            leaf_hash,
            merkle_proof,
            timestamp,
            signature: sig_bytes.to_vec(),
        }
    }

    /// Verify a fraud proof's signature against the validator's public key.
    pub fn verify_fraud_proof(proof: &FraudProof, validator_pubkey: &[u8; 32]) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(validator_pubkey) {
            Ok(vk) => vk,
            Err(_) => return false,
        };

        let signature = match ed25519_dalek::Signature::from_slice(&proof.signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        let msg = Self::fraud_proof_signing_message(
            &proof.validator_node_id,
            &proof.expected_root,
            &proof.actual_root,
            proof.leaf_index,
            &proof.leaf_hash,
            &proof.merkle_proof,
            proof.timestamp,
        );

        verifying_key.verify(&msg, &signature).is_ok()
    }

    /// Submit a fraud proof. Placeholder: logs the proof.
    ///
    /// In production this would submit the proof to Solana via a
    /// fraud-proof instruction.
    pub fn submit_fraud_proof(proof: &FraudProof, rpc_url: &str) -> Result<()> {
        tracing::info!(
            validator = %proof.validator_node_id,
            %rpc_url,
            leaf_index = proof.leaf_index,
            "submitting fraud proof (placeholder)"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_root_valid() {
        let root = [0xAA; 32];
        let result = ValidatorLogic::check_root(root, root);
        assert_eq!(result, RootCheckResult::Valid);
    }

    #[test]
    fn test_check_root_invalid() {
        let on_chain = [0xAA; 32];
        let broadcast = [0xBB; 32];
        let result = ValidatorLogic::check_root(broadcast, on_chain);
        assert_eq!(
            result,
            RootCheckResult::Invalid {
                expected: on_chain,
                got: broadcast,
            }
        );
    }

    #[test]
    fn test_generate_and_verify_fraud_proof() {
        let validator = Validator::from_secret("test-node".into(), [7u8; 32]);

        let expected_root = [0xAA; 32];
        let actual_root = [0xBB; 32];
        let leaf_hash = [0xCC; 32];
        let merkle_proof = vec![[0x11; 32], [0x22; 32], [0x33; 32]];

        let proof = ValidatorLogic::generate_fraud_proof(
            &validator,
            expected_root,
            actual_root,
            5,
            leaf_hash,
            merkle_proof.clone(),
        );

        let pubkey = validator.vrf_keypair.public_key_bytes();
        assert!(ValidatorLogic::verify_fraud_proof(&proof, &pubkey));
    }

    #[test]
    fn test_verify_fraud_proof_wrong_key() {
        let validator = Validator::from_secret("test-node".into(), [7u8; 32]);
        let other = Validator::from_secret("other-node".into(), [8u8; 32]);

        let proof = ValidatorLogic::generate_fraud_proof(
            &validator,
            [0xAA; 32],
            [0xBB; 32],
            1,
            [0xCC; 32],
            vec![[0x11; 32]],
        );

        let wrong_pubkey = other.vrf_keypair.public_key_bytes();
        assert!(!ValidatorLogic::verify_fraud_proof(&proof, &wrong_pubkey));
    }

    #[test]
    fn test_verify_fraud_proof_tampered() {
        let validator = Validator::from_secret("test-node".into(), [9u8; 32]);
        let mut proof = ValidatorLogic::generate_fraud_proof(
            &validator,
            [0xAA; 32],
            [0xBB; 32],
            1,
            [0xCC; 32],
            vec![[0x11; 32]],
        );

        let pubkey = validator.vrf_keypair.public_key_bytes();

        // Tamper with the actual_root — signature should no longer match.
        proof.actual_root[0] ^= 0x01;
        assert!(!ValidatorLogic::verify_fraud_proof(&proof, &pubkey));
    }

    #[test]
    fn test_submit_fraud_proof_placeholder() {
        let validator = Validator::from_secret("test-node".into(), [3u8; 32]);
        let proof = ValidatorLogic::generate_fraud_proof(
            &validator,
            [0xAA; 32],
            [0xBB; 32],
            0,
            [0xCC; 32],
            vec![],
        );
        let result = ValidatorLogic::submit_fraud_proof(&proof, "https://api.devnet.solana.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validator_new_has_keys() {
        let v = Validator::new("fresh".into());
        let bytes = v.vrf_keypair.public_key_bytes();
        // Public key should be 32 bytes (guaranteed by type) and non-zero.
        assert_ne!(bytes, [0u8; 32]);
    }
}
