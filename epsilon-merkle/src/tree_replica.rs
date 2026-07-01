//! Off-chain Merkle tree replica.
//!
//! Maintains a local copy of the on-chain Merkle tree using SHA-256
//! (prototype; production uses Poseidon hash matching Light Protocol).
//! Generates inclusion proofs for clients.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default tree height for state trees (Light Protocol uses 26)
pub const TREE_HEIGHT: usize = 26;

/// A Merkle inclusion proof: sibling hashes from leaf to root
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub leaf_index: u64,
    pub merkle_tree: [u8; 32],
    pub proof: Vec<[u8; 32]>,
    pub root: [u8; 32],
    pub root_seq: u64,
}

/// Off-chain Merkle tree replica.
/// Stores all leaves and computes proofs.
pub struct TreeReplica {
    tree_pubkey: [u8; 32],
    height: usize,
    /// All leaves indexed by position: leaf_index → hash
    leaves: Vec<Option<[u8; 32]>>,
    /// Current root
    root: [u8; 32],
    /// Root sequence number
    root_seq: u64,
    /// Next leaf index (where new leaves get appended)
    next_index: u64,
}

impl TreeReplica {
    pub fn new(tree_pubkey: [u8; 32], height: usize) -> Self {
        let capacity = 1usize << height.min(20); // cap at 1M for prototype
        Self {
            tree_pubkey,
            height,
            leaves: vec![None; capacity],
            root: [0u8; 32],
            root_seq: 0,
            next_index: 0,
        }
    }

    /// Append a leaf at the next available position
    pub fn append_leaf(&mut self, leaf_hash: [u8; 32]) -> u64 {
        let index = self.next_index;
        if (index as usize) < self.leaves.len() {
            self.leaves[index as usize] = Some(leaf_hash);
            self.next_index += 1;
            self.recompute_root();
            self.root_seq += 1;
        }
        index
    }

    /// Update a leaf at a specific index (for nullify operations)
    pub fn update_leaf(&mut self, index: u64, leaf_hash: [u8; 32]) {
        if (index as usize) < self.leaves.len() {
            self.leaves[index as usize] = Some(leaf_hash);
            self.recompute_root();
            self.root_seq += 1;
        }
    }

    /// Generate an inclusion proof for a leaf at given index
    pub fn generate_proof(&self, leaf_index: u64) -> Option<MerkleProof> {
        let idx = leaf_index as usize;
        if idx >= self.leaves.len() {
            return None;
        }
        let leaf = self.leaves[idx]?;

        // Build the full tree level by level to get sibling hashes
        let mut levels: Vec<Vec<[u8; 32]>> = Vec::with_capacity(self.height + 1);
        // Level 0 = leaves
        levels.push(
            self.leaves
                .iter()
                .map(|l| l.unwrap_or([0u8; 32]))
                .collect(),
        );
        for _ in 0..self.height {
            let prev = levels.last().unwrap();
            let mut next: Vec<[u8; 32]> = Vec::with_capacity(prev.len() / 2);
            for pair in prev.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or([0u8; 32]);
                next.push(hash_pair(&left, &right));
            }
            levels.push(next);
        }

        // Build proof: sibling hash at each level
        let mut proof: Vec<[u8; 32]> = Vec::with_capacity(self.height);
        let mut current_index = idx;

        for level in 0..self.height {
            let sibling_index = current_index ^ 1;
            let level_data = &levels[level];
            let sibling = if sibling_index < level_data.len() {
                level_data[sibling_index]
            } else {
                [0u8; 32]
            };
            proof.push(sibling);
            current_index >>= 1;
        }

        Some(MerkleProof {
            leaf,
            leaf_index,
            merkle_tree: self.tree_pubkey,
            proof,
            root: self.root,
            root_seq: self.root_seq,
        })
    }

    /// Verify a proof (for testing / incoming proofs from peers)
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;
        let mut index = proof.leaf_index as usize;

        for sibling in &proof.proof {
            if index % 2 == 0 {
                current = hash_pair(&current, sibling);
            } else {
                current = hash_pair(sibling, &current);
            }
            index >>= 1;
        }

        current == proof.root
    }

    /// Get current root
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get current root sequence
    pub fn root_seq(&self) -> u64 {
        self.root_seq
    }

    /// Get leaf count
    pub fn leaf_count(&self) -> u64 {
        self.next_index
    }

    /// Get a leaf by index
    pub fn get_leaf(&self, index: u64) -> Option<[u8; 32]> {
        self.leaves.get(index as usize).and_then(|l| *l)
    }

    /// Recompute root from all leaves
    fn recompute_root(&mut self) {
        // Build tree level by level
        let mut current_level: Vec<[u8; 32]> = self
            .leaves
            .iter()
            .map(|l| l.unwrap_or([0u8; 32]))
            .collect();

        for _ in 0..self.height {
            let mut next_level: Vec<[u8; 32]> = Vec::with_capacity(current_level.len() / 2);
            for pair in current_level.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or([0u8; 32]);
                next_level.push(hash_pair(&left, &right));
            }
            current_level = next_level;
            if current_level.len() <= 1 {
                break;
            }
        }

        self.root = current_level.first().copied().unwrap_or([0u8; 32]);
    }

    /// Bulk init from leaf entries (for loading from LeafStore)
    pub fn init_from_leaves(&mut self, leaves: &[(u64, [u8; 32])]) {
        for (index, hash) in leaves {
            if (*index as usize) < self.leaves.len() {
                self.leaves[*index as usize] = Some(*hash);
                if *index >= self.next_index {
                    self.next_index = index + 1;
                }
            }
        }
        self.recompute_root();
    }
}

/// Hash two child nodes into a parent node
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_proof() {
        let tree_key = [1u8; 32];
        let mut tree = TreeReplica::new(tree_key, 4); // small tree for test

        // Append 3 leaves
        let leaf1 = [0xAA; 32];
        let leaf2 = [0xBB; 32];
        let leaf3 = [0xCC; 32];

        tree.append_leaf(leaf1);
        tree.append_leaf(leaf2);
        tree.append_leaf(leaf3);

        assert_eq!(tree.leaf_count(), 3);

        // Generate proof for leaf 0
        let proof = tree.generate_proof(0).unwrap();
        assert_eq!(proof.leaf, leaf1);
        assert!(TreeReplica::verify_proof(&proof));

        // Generate proof for leaf 2
        let proof2 = tree.generate_proof(2).unwrap();
        assert_eq!(proof2.leaf, leaf3);
        assert!(TreeReplica::verify_proof(&proof2));
    }

    #[test]
    fn test_update_leaf() {
        let tree_key = [2u8; 32];
        let mut tree = TreeReplica::new(tree_key, 4);

        tree.append_leaf([0xAA; 32]);
        tree.append_leaf([0xBB; 32]);

        let root_before = tree.root();

        // Update leaf 0
        tree.update_leaf(0, [0xDD; 32]);
        let root_after = tree.root();

        assert_ne!(root_before, root_after);

        // Proof for updated leaf
        let proof = tree.generate_proof(0).unwrap();
        assert!(TreeReplica::verify_proof(&proof));
    }

    #[test]
    fn test_empty_tree() {
        let tree_key = [3u8; 32];
        let tree = TreeReplica::new(tree_key, 4);

        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.root(), [0u8; 32]);
    }
}