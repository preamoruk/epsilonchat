//! Proof requester — phone-side: requests proofs from forester via Iroh.
//!
//! Phone stores only its own leaves. When it needs to make a
//! transfer, it requests a Merkle proof from the forester (desktop)
//! via Iroh DHT/gossip.

use anyhow::Result;
use solana_sdk::pubkey::Pubkey;

use crate::leaf_store::LeafStore;
use crate::tree_replica::MerkleProof;

/// Proof requester runs on the phone.
/// Stores only owned leaves, requests proofs when needed.
pub struct ProofRequester {
    store: LeafStore,
    owner: Pubkey,
}

impl ProofRequester {
    pub fn new(data_dir: &str, owner: Pubkey) -> Self {
        let store = LeafStore::new_filtered(data_dir, owner);
        Self { store, owner }
    }

    /// Get my leaves (my token balances)
    pub async fn my_balance(&self) -> Vec<crate::leaf_store::LeafEntry> {
        self.store.get_by_owner(&self.owner).await
    }

    /// Get my leaf count
    pub async fn my_leaf_count(&self) -> usize {
        self.store.get_by_owner(&self.owner).await.len()
    }

    /// Request a proof from the forester via Iroh
    /// In prototype: just queries local store if forester mode
    pub async fn request_proof(
        &self,
        _endpoint: &iroh::Endpoint,
        _tree: &[u8; 32],
        leaf_index: u64,
    ) -> Option<MerkleProof> {
        // In production: send ProofRequest via Iroh gossip to forester
        // Forester responds with ProofResponse
        // Phone verifies proof locally

        // Prototype: not connected to forester yet
        tracing::warn!(
            "Proof request: would query forester via Iroh (not implemented in prototype)"
        );
        None
    }

    /// Receive a leaf update from Iroh gossip
    pub async fn receive_leaf_update(&self, entry: crate::leaf_store::LeafEntry) -> bool {
        self.store.upsert(entry).await
    }
}

/// Run the phone client
pub async fn run_phone(rpc_url: &str, owner: &str, data_dir: &str) -> Result<()> {
    let owner_pubkey: Pubkey = owner
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid owner pubkey: {e}"))?;

    let requester = ProofRequester::new(data_dir, owner_pubkey);

    // Load existing leaves from disk
    requester.store.load_from_disk().await.ok();

    let endpoint = crate::gossip::create_endpoint(data_dir).await?;

    println!("\n=== EpsilonChat Phone Client ===");
    println!("Node ID: {}", endpoint.id());
    println!("Owner: {}", owner_pubkey);
    println!("RPC: {}", rpc_url);
    println!("Data dir: {}", data_dir);

    let balance = requester.my_balance().await;
    println!("\n--- My Token Accounts ---");
    if balance.is_empty() {
        println!("(no compressed accounts yet)");
    } else {
        for (i, leaf) in balance.iter().enumerate() {
            println!(
                "  #{}: leaf_index={}, lamports={}, slot={}",
                i, leaf.leaf_index, leaf.lamports, leaf.slot
            );
        }
    }
    println!("-------------------------\n");
    println!("Press Ctrl+C to stop.\n");

    tokio::signal::ctrl_c().await?;
    Ok(())
}
