//! Leaf storage — local persistence of Merkle tree leaves.
//!
//! Two modes:
//! - Forester (desktop): stores ALL leaves for a tree (full index)
//! - Phone: stores only leaves where owner == self.owner (just own balance)

use anyhow::Result;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::path::Path;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

type LeafMap = HashMap<[u8; 32], LeafEntry>;
type OwnerMap = HashMap<[u8; 32], Vec<[u8; 32]>>;
type RootMap = HashMap<[u8; 32], ([u8; 32], u64)>;


/// A Merkle tree leaf as stored in the mesh.
/// This is the data that gets gossip-broadcast between peers.
#[derive(Clone, Debug, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct LeafEntry {
    /// Poseidon hash of the CompressedAccount (the leaf value in the tree)
    pub leaf_hash: [u8; 32],
    /// Position in the Merkle tree
    pub leaf_index: u64,
    /// Pubkey of the Merkle tree this leaf belongs to
    pub merkle_tree: [u8; 32],
    /// Owner of the compressed account (so phones can filter "is this mine?")
    pub owner: [u8; 32],
    /// Lamports held by this compressed account
    pub lamports: u64,
    /// Current root of the tree (updated on each batch_append)
    pub root: [u8; 32],
    /// Root sequence number (incremented on each root update)
    pub root_seq: u64,
    /// Slot when this leaf was last updated
    pub slot: u64,
}

impl LeafEntry {
    /// Check if this leaf belongs to the given owner
    pub fn belongs_to(&self, owner: &Pubkey) -> bool {
        self.owner == owner.to_bytes()
    }

    /// Compact binary encoding for Iroh gossip messages
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).unwrap_or_default()
    }

    /// Decode from Iroh gossip message bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        borsh::from_slice(data).ok()
    }
}

/// In-memory + disk leaf storage.
/// Forester stores all leaves. Phone stores only owned leaves.
#[derive(Clone)]
pub struct LeafStore {
    // leaf_hash → LeafEntry
    leaves: Arc<RwLock<LeafMap>>,
    // owner pubkey → set of leaf_hashes (for quick "what are my leaves?" lookup)
    by_owner: Arc<RwLock<OwnerMap>>,
    // merkle_tree pubkey → current root + root_seq
    tree_roots: Arc<RwLock<RootMap>>,
    // Storage mode
    mode: StoreMode,
    // If Phone mode: only store leaves for this owner
    owner_filter: Option<Pubkey>,
    // Data directory for disk persistence
    data_dir: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreMode {
    /// Store everything (desktop forester)
    Full,
    /// Store only leaves where owner == owner_filter (phone)
    Filtered,
}

impl LeafStore {
    pub fn new_full(data_dir: impl AsRef<Path>) -> Self {
        Self {
            leaves: Arc::new(RwLock::new(HashMap::new())),
            by_owner: Arc::new(RwLock::new(HashMap::new())),
            tree_roots: Arc::new(RwLock::new(HashMap::new())),
            mode: StoreMode::Full,
            owner_filter: None,
            data_dir: data_dir.as_ref().to_string_lossy().to_string(),
        }
    }

    pub fn new_filtered(data_dir: impl AsRef<Path>, owner: Pubkey) -> Self {
        Self {
            leaves: Arc::new(RwLock::new(HashMap::new())),
            by_owner: Arc::new(RwLock::new(HashMap::new())),
            tree_roots: Arc::new(RwLock::new(HashMap::new())),
            mode: StoreMode::Filtered,
            owner_filter: Some(owner),
            data_dir: data_dir.as_ref().to_string_lossy().to_string(),
        }
    }

    /// Insert or update a leaf. In Filtered mode, ignores leaves
    /// not owned by the filter owner.
    pub async fn upsert(&self, entry: LeafEntry) -> bool {
        // Filter check for phone mode
        if self.mode == StoreMode::Filtered {
            if let Some(owner) = &self.owner_filter {
                if !entry.belongs_to(owner) {
                    return false; // Not our leaf, skip
                }
            }
        }

        let leaf_hash = entry.leaf_hash;
        let owner = entry.owner;

        // Update tree root
        self.tree_roots
            .write()
            .await
            .insert(entry.merkle_tree, (entry.root, entry.root_seq));

        // Insert leaf
        self.leaves.write().await.insert(leaf_hash, entry);

        // Update owner index
        self.by_owner
            .write()
            .await
            .entry(owner)
            .or_default()
            .push(leaf_hash);

        tracing::debug!(
            leaf_index = ?hash_short(&leaf_hash),
            "Leaf stored (total: {})",
            self.leaves.read().await.len()
        );
        true
    }

    /// Get a leaf by its hash
    pub async fn get(&self, leaf_hash: &[u8; 32]) -> Option<LeafEntry> {
        self.leaves.read().await.get(leaf_hash).cloned()
    }

    /// Get all leaves for an owner (phone: "what's my balance?")
    pub async fn get_by_owner(&self, owner: &Pubkey) -> Vec<LeafEntry> {
        let by_owner = self.by_owner.read().await;
        let leaves = self.leaves.read().await;
        by_owner
            .get(&owner.to_bytes())
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| leaves.get(h).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all leaves for a specific Merkle tree (forester: build proof)
    pub async fn get_by_tree(&self, tree: &[u8; 32]) -> Vec<LeafEntry> {
        self.leaves
            .read()
            .await
            .values()
            .filter(|e| &e.merkle_tree == tree)
            .cloned()
            .collect()
    }

    /// Get current root for a tree
    pub async fn get_root(&self, tree: &[u8; 32]) -> Option<([u8; 32], u64)> {
        self.tree_roots.read().await.get(tree).copied()
    }

    /// Total leaf count
    pub async fn count(&self) -> usize {
        self.leaves.read().await.len()
    }

    /// Get all stored leaf hashes (for tree_replica to build/update tree)
    pub async fn all_leaves_for_tree(&self, tree: &[u8; 32]) -> Vec<(u64, [u8; 32])> {
        self.leaves
            .read()
            .await
            .values()
            .filter(|e| &e.merkle_tree == tree)
            .map(|e| (e.leaf_index, e.leaf_hash))
            .collect()
    }

    /// Persist to disk (simple JSON dump for prototype)
    pub async fn save_to_disk(&self) -> Result<()> {
        let dir = std::path::Path::new(&self.data_dir);
        tokio::fs::create_dir_all(dir).await.ok();

        let leaves: Vec<LeafEntry> = self.leaves.read().await.values().cloned().collect();
        let json = serde_json::to_vec_pretty(&leaves)?;
        let path = dir.join("leaves.json");
        tokio::fs::write(path, json).await?;

        tracing::info!("Saved {} leaves to disk", leaves.len());
        Ok(())
    }

    /// Load from disk
    pub async fn load_from_disk(&self) -> Result<()> {
        let path = std::path::Path::new(&self.data_dir).join("leaves.json");
        let data = tokio::fs::read(&path).await?;
        let leaves: Vec<LeafEntry> = serde_json::from_slice(&data)?;

        let count = leaves.len();
        for entry in leaves {
            self.upsert(entry).await;
        }

        tracing::info!("Loaded {} leaves from disk", count);
        Ok(())
    }
}

/// Format a hash for short display (first 8 hex chars)
fn hash_short(hash: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(&hash[..4])
}