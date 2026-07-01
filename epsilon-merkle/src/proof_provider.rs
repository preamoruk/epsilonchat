//! Proof provider — serves Merkle proofs to phone peers via Iroh.
//!
//! Forester listens for ProofRequest messages on Iroh gossip
//! and responds with MerkleProof from its local TreeReplica.

use anyhow::Result;
use iroh::Endpoint;
use std::sync::Arc;

use crate::leaf_store::LeafStore;
use crate::tree_replica::{MerkleProof, TreeReplica};

/// Proof provider runs on the forester (desktop).
/// Listens for proof requests and serves them.
pub struct ProofProvider {
    tree: Arc<tokio::sync::Mutex<TreeReplica>>,
    store: LeafStore,
}

impl ProofProvider {
    pub fn new(tree: Arc<tokio::sync::Mutex<TreeReplica>>, store: LeafStore) -> Self {
        Self { tree, store }
    }

    /// Handle a proof request: look up leaf, generate proof
    pub async fn handle_proof_request(
        &self,
        merkle_tree: &[u8; 32],
        leaf_index: u64,
    ) -> Option<MerkleProof> {
        let tree = self.tree.lock().await;
        tree.generate_proof(leaf_index)
    }

    /// Serve proofs over Iroh (placeholder: real impl uses gossip RPC)
    pub async fn run(self, _endpoint: Endpoint) -> Result<()> {
        tracing::info!("Proof provider started, waiting for requests...");

        // In production: listen on Iroh gossip for ProofRequest messages
        // and respond with ProofResponse.
        // Prototype: proofs are requested directly via CLI.

        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}