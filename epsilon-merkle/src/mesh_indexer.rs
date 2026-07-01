//! Mesh indexer — listens to Solana for Merkle tree updates.
//!
//! In production: subscribes to account_compression program via
//! Solana PubSub and parses NOOP events from transaction logs.
//! In prototype: polls Solana RPC for confirmed transactions
//! involving the target Merkle tree, extracts leaf data.
// stores them in LeafStore, updates TreeReplica, and
// broadcasts via Iroh gossip.

use anyhow::{Context, Result};
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::time::Duration;

use crate::leaf_store::{LeafEntry, LeafStore};
use crate::tree_replica::TreeReplica;

// Polls Solana for Merkle tree updates, extracts leaves,
// stores them in LeafStore, updates TreeReplica, and
// broadcasts via Iroh gossip.
pub struct MeshIndexer {
    rpc: RpcClient,
    tree_pubkey: Pubkey,
    tree_bytes: [u8; 32],
    store: LeafStore,
    tree: tokio::sync::Mutex<TreeReplica>,
    last_slot: u64,
}

impl MeshIndexer {
    pub fn new(rpc_url: &str, tree_pubkey: &str, store: LeafStore) -> Result<Self> {
        let rpc = RpcClient::new_with_timeout(
            rpc_url.to_string(),
            Duration::from_secs(30),
        );
        let tree_pubkey: Pubkey = tree_pubkey
            .parse()
            .context("Invalid Merkle tree pubkey")?;
        let tree_bytes = tree_pubkey.to_bytes();

        let tree = TreeReplica::new(tree_bytes, crate::tree_replica::TREE_HEIGHT);

        Ok(Self {
            rpc,
            tree_pubkey,
            tree_bytes,
            store,
            tree: tokio::sync::Mutex::new(tree),
            last_slot: 0,
        })
    }

    /// Run the indexer loop: poll for new blocks, extract leaves
    pub async fn run(&mut self) -> Result<()> {
        tracing::info!("Mesh indexer started for tree: {}", self.tree_pubkey);
        tracing::info!("Polling Solana every 10 seconds...");

        // Load existing leaves from disk
        self.store.load_from_disk().await.ok();

        loop {
            match self.poll_once().await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("Processed {} new leaves", count);
                    }
                }
                Err(e) => {
                    tracing::warn!("Poll error: {e:#}");
                }
            }

            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    /// Poll Solana for new transactions since last_slot
    /// Returns the number of new leaves found
    async fn poll_once(&mut self) -> Result<usize> {
        // Get current slot
        let current_slot = self.rpc.get_slot()?;

        if current_slot <= self.last_slot {
            return Ok(0);
        }

        // In production: use getSignaturesForAddress + getTransaction
        // to parse NOOP events from logs.
        // In prototype: we simulate by checking the tree account directly.

        let account_info = self.rpc.get_account(&self.tree_pubkey);

        match account_info {
            Ok(_account) => {
                // Real implementation would parse the account data
                // to extract queue items, then build LeafEntry from each.
                // For prototype: just update the slot counter.
                self.last_slot = current_slot;
            }
            Err(e) => {
                tracing::debug!("Tree account not found (devnet): {e}");
                self.last_slot = current_slot;
            }
        }

        Ok(0)
    }

    /// Manually inject a leaf (for testing / manual mint)
    pub async fn inject_leaf(&self, entry: LeafEntry) -> Result<()> {
        let stored = self.store.upsert(entry.clone()).await;

        if stored {
            let mut tree = self.tree.lock().await;
            let index = entry.leaf_index;
            let hash = entry.leaf_hash;
            tree.append_leaf(hash);

            tracing::info!(
                "Leaf injected: index={}, root_seq={}",
                index,
                tree.root_seq()
            );
        }

        self.store.save_to_disk().await?;
        Ok(())
    }

    /// Get a proof for a leaf (forester serves proofs)
    pub async fn get_proof(&self, leaf_index: u64) -> Option<crate::tree_replica::MerkleProof> {
        let tree = self.tree.lock().await;
        tree.generate_proof(leaf_index)
    }

    /// Get current root
    pub async fn root(&self) -> [u8; 32] {
        self.tree.lock().await.root()
    }

    /// Get leaf count
    pub async fn leaf_count(&self) -> u64 {
        self.tree.lock().await.leaf_count()
    }

    /// Get the underlying store (for gossip broadcast)
    pub fn store(&self) -> &LeafStore {
        &self.store
    }
}

/// Run the forester: full indexer + proof provider
pub async fn run_forester(rpc_url: &str, tree_pubkey: &str, data_dir: &str) -> Result<()> {
    let store = LeafStore::new_full(data_dir);
    let mut indexer = MeshIndexer::new(rpc_url, tree_pubkey, store)?;

    // Start indexer in background
    let indexer_handle = tokio::spawn(async move {
        indexer.run().await
    });

    // Start Iroh endpoint for serving proofs
    let endpoint = crate::gossip::create_endpoint(data_dir).await?;

    println!("\n=== EpsilonChat Forester ===");
    println!("Node ID: {}", endpoint.id());
    println!("Tree: {}", tree_pubkey);
    println!("RPC: {}", rpc_url);
    println!("Data dir: {}", data_dir);
    println!("\nTo connect a phone:");
    println!("  epsilon-merkle invite  (generate invite link)");
    println!("\nPress Ctrl+C to stop.\n");

    // Keep running
    tokio::select! {
        _ = indexer_handle => {
            tracing::warn!("Indexer stopped");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutting down forester");
        }
    }

    Ok(())
}