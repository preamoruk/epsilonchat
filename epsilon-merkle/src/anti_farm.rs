//! Anti-farm Sybil resistance for EpsilonChat.
//!
//! Prevents reward farming by requiring nodes to stake EPS tokens and by
//! detecting topologically co-located clusters (farms) via latency analysis.
//! Nodes in detected farms have their rewards scaled down by a uniqueness
//! factor and may be slashed.
//!
//! Three layers of defence:
//! 1. **StakeManager** — economic stake requirement (Sybil cost)
//! 2. **TopologicalUniqueness** — network-topology cluster detection
//! 3. **FarmDetector** — combines both to assess and penalise farms

use solana_sdk::pubkey::Pubkey;
use std::collections::{HashMap, HashSet};

/// 10 EPS in lamports (1 EPS = 10^9 lamports).
pub const DEFAULT_MIN_STAKE: u64 = 10_000_000_000;
/// 2 ms expressed in nanoseconds — below this latency two nodes are co-located.
pub const DEFAULT_CLUSTER_THRESHOLD_NS: u64 = 2_000_000;
/// Cluster membership above this is flagged as a farm.
pub const DEFAULT_FARM_SIZE_THRESHOLD: usize = 10;

// ---------------------------------------------------------------------------
// StakeManager
// ---------------------------------------------------------------------------

/// Manages staked EPS amounts per node and enforces a minimum stake to earn.
#[derive(Debug, Clone)]
pub struct StakeManager {
    /// node_id → staked EPS amount (lamports).
    pub stakes: HashMap<Pubkey, u64>,
    /// Minimum stake (lamports) required to earn rewards.
    pub min_stake: u64,
}

impl Default for StakeManager {
    fn default() -> Self {
        Self {
            stakes: HashMap::new(),
            min_stake: DEFAULT_MIN_STAKE,
        }
    }
}

impl StakeManager {
    /// Create a new StakeManager with the given minimum stake (lamports).
    pub fn new(min_stake: u64) -> Self {
        Self {
            stakes: HashMap::new(),
            min_stake,
        }
    }

    /// Register or update a stake for `node`.
    ///
    /// If the node already has a stake, the amount is added to it.
    pub fn register_stake(&mut self, node: Pubkey, amount: u64) {
        let entry = self.stakes.entry(node).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    /// Set a node's stake to an exact amount, overwriting any previous value.
    pub fn set_stake(&mut self, node: Pubkey, amount: u64) {
        self.stakes.insert(node, amount);
    }

    /// Returns true if the node's stake is at least `min_stake`.
    pub fn can_earn(&self, node: &Pubkey) -> bool {
        self.get_stake(node) >= self.min_stake
    }

    /// Returns the staked amount for `node`, or 0 if unregistered.
    pub fn get_stake(&self, node: &Pubkey) -> u64 {
        self.stakes.get(node).copied().unwrap_or(0)
    }

    /// Reduce a node's stake by `amount` (clamped to the actual stake).
    ///
    /// Returns the actual amount slashed (may be less than requested if the
    /// stake was smaller than `amount`).
    pub fn slash(&mut self, node: &Pubkey, amount: u64) -> u64 {
        let current = self.get_stake(node);
        let slashed = amount.min(current);
        if slashed > 0 {
            let remaining = current - slashed;
            if remaining == 0 {
                self.stakes.remove(node);
            } else {
                self.stakes.insert(*node, remaining);
            }
        }
        slashed
    }

    /// Withdraw the full stake for `node`.
    ///
    /// Returns the amount withdrawn (0 if the node had no stake).
    pub fn unstake(&mut self, node: &Pubkey) -> u64 {
        self.stakes.remove(node).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// TopologicalUniqueness
// ---------------------------------------------------------------------------

/// Detects co-located node clusters from pairwise latency measurements.
///
/// Two nodes are considered co-located when the latency between them is below
/// `cluster_threshold_ms`. Clusters are computed transitively: if A is
/// co-located with B and B with C, then A, B, C form a single cluster.
#[derive(Debug, Clone)]
pub struct TopologicalUniqueness {
    /// node → list of (peer_node, latency_ns) measurements.
    pub peer_latencies: HashMap<Pubkey, Vec<(Pubkey, u64)>>,
    /// Latency below this (in nanoseconds) means co-located.
    pub cluster_threshold_ns: u64,
}

impl Default for TopologicalUniqueness {
    fn default() -> Self {
        Self {
            peer_latencies: HashMap::new(),
            cluster_threshold_ns: DEFAULT_CLUSTER_THRESHOLD_NS,
        }
    }
}

impl TopologicalUniqueness {
    /// Create with a custom cluster threshold in nanoseconds.
    pub fn new(cluster_threshold_ns: u64) -> Self {
        Self {
            peer_latencies: HashMap::new(),
            cluster_threshold_ns,
        }
    }

    /// Record a latency measurement from `node` to `peer` (in nanoseconds).
    pub fn record_latency(&mut self, node: Pubkey, peer: Pubkey, latency_ns: u64) {
        self.peer_latencies
            .entry(node)
            .or_default()
            .push((peer, latency_ns));
    }

    /// Returns true if `a` and `b` are co-located based on recorded latencies.
    ///
    /// Looks for *any* recorded measurement between the two nodes (in either
    /// direction) that is below the threshold.
    fn is_colocated(&self, a: &Pubkey, b: &Pubkey) -> bool {
        if let Some(peers) = self.peer_latencies.get(a) {
            for (peer, lat) in peers {
                if peer == b && *lat < self.cluster_threshold_ns {
                    return true;
                }
            }
        }
        if let Some(peers) = self.peer_latencies.get(b) {
            for (peer, lat) in peers {
                if peer == a && *lat < self.cluster_threshold_ns {
                    return true;
                }
            }
        }
        false
    }

    /// Detect the co-located cluster containing `node` using transitive closure.
    ///
    /// Returns a vector of all Pubkeys in the cluster (including `node`
    /// itself). If the node has no co-located peers, returns `vec![node]`.
    pub fn detect_cluster(&self, node: &Pubkey) -> Vec<Pubkey> {
        let mut cluster: HashSet<Pubkey> = HashSet::new();
        cluster.insert(*node);
        let mut frontier: Vec<Pubkey> = vec![*node];

        while let Some(current) = frontier.pop() {
            // Gather all known peers (in either direction) for BFS expansion.
            let mut candidates: Vec<Pubkey> = Vec::new();
            if let Some(peers) = self.peer_latencies.get(&current) {
                for (peer, _) in peers {
                    candidates.push(*peer);
                }
            }
            // Also check measurements recorded *by* other nodes pointing at
            // `current` — those peers are candidates too.
            for (other, peers) in &self.peer_latencies {
                if other == &current {
                    continue;
                }
                for (peer, _) in peers {
                    if peer == &current {
                        candidates.push(*other);
                    }
                }
            }

            for cand in candidates {
                if cluster.contains(&cand) {
                    continue;
                }
                if self.is_colocated(&current, &cand) {
                    cluster.insert(cand);
                    frontier.push(cand);
                }
            }
        }

        cluster.into_iter().collect()
    }

    /// Uniqueness score: 1.0 if the node is isolated, otherwise 1/cluster_size.
    pub fn uniqueness_score(&self, node: &Pubkey) -> f64 {
        let cluster = self.detect_cluster(node);
        let size = cluster.len();
        if size == 0 {
            return 1.0;
        }
        1.0 / size as f64
    }

    /// Flag a node as part of a farm: cluster size > 10 and uniqueness < 0.1.
    pub fn flag_farm(&self, node: &Pubkey) -> bool {
        let cluster = self.detect_cluster(node);
        let size = cluster.len();
        let uniqueness = 1.0 / size as f64;
        size > DEFAULT_FARM_SIZE_THRESHOLD && uniqueness < 0.1
    }
}

// ---------------------------------------------------------------------------
// NodeAssessment
// ---------------------------------------------------------------------------

/// Snapshot of a node's anti-farm assessment.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeAssessment {
    pub node_id: Pubkey,
    pub stake: u64,
    pub uniqueness: f64,
    pub is_farm: bool,
    pub reward_multiplier: f64,
    pub estimated_reward: u64,
}

// ---------------------------------------------------------------------------
// FarmDetector
// ---------------------------------------------------------------------------

/// Combines stake management and topology to detect and penalise farms.
#[derive(Debug, Clone)]
pub struct FarmDetector {
    pub topology: TopologicalUniqueness,
    pub stakes: StakeManager,
    pub farm_size_threshold: usize,
}

impl Default for FarmDetector {
    fn default() -> Self {
        Self {
            topology: TopologicalUniqueness::default(),
            stakes: StakeManager::default(),
            farm_size_threshold: DEFAULT_FARM_SIZE_THRESHOLD,
        }
    }
}

impl FarmDetector {
    /// Create with a custom farm size threshold.
    pub fn new(farm_size_threshold: usize) -> Self {
        Self {
            topology: TopologicalUniqueness::default(),
            stakes: StakeManager::default(),
            farm_size_threshold,
        }
    }

    /// Assess a node: stake, uniqueness, farm flag, reward multiplier, and
    /// estimated reward for a nominal base reward of 1 EPS (10^9 lamports).
    pub fn assess_node(&self, node: &Pubkey) -> NodeAssessment {
        let stake = self.stakes.get_stake(node);
        let cluster = self.topology.detect_cluster(node);
        let cluster_size = cluster.len();
        let uniqueness = if cluster_size == 0 {
            1.0
        } else {
            1.0 / cluster_size as f64
        };
        let is_farm = cluster_size > self.farm_size_threshold && uniqueness < 0.1;
        let can_earn = self.stakes.can_earn(node) as u8 as f64;
        let reward_multiplier = uniqueness * can_earn;
        let base_reward: u64 = 1_000_000_000; // 1 EPS
        let estimated_reward = (base_reward as f64 * reward_multiplier) as u64;

        NodeAssessment {
            node_id: *node,
            stake,
            uniqueness,
            is_farm,
            reward_multiplier,
            estimated_reward,
        }
    }

    /// Slash all nodes in a detected farm by 50% of their current stake.
    ///
    /// Returns a list of (node, slashed_amount) for every node that lost
    /// stake. Nodes with no stake are skipped.
    pub fn slash_farm(&mut self, cluster: &[Pubkey]) -> Vec<(Pubkey, u64)> {
        let mut slashed = Vec::new();
        for node in cluster {
            let stake = self.stakes.get_stake(node);
            if stake == 0 {
                continue;
            }
            let slash_amount = stake / 2;
            let actual = self.stakes.slash(node, slash_amount);
            if actual > 0 {
                slashed.push((*node, actual));
            }
        }
        slashed
    }

    /// Compute the reward for a node given a base reward amount.
    ///
    /// `base_reward * uniqueness * (can_earn ? 1 : 0)`, truncated to u64.
    pub fn reward_for_node(&self, node: &Pubkey, base_reward: u64) -> u64 {
        let uniqueness = self.topology.uniqueness_score(node);
        let can_earn = self.stakes.can_earn(node) as u8 as f64;
        (base_reward as f64 * uniqueness * can_earn) as u64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: deterministic Pubkey from a byte slice.
    fn pk(b: &[u8; 32]) -> Pubkey {
        Pubkey::new_from_array(*b)
    }

    fn pk_from_u8(n: u8) -> Pubkey {
        let mut arr = [0u8; 32];
        arr[0] = n;
        pk(&arr)
    }

    // --- StakeManager tests ---

    #[test]
    fn test_stake_registration_and_min_check() {
        let mut sm = StakeManager::new(DEFAULT_MIN_STAKE);
        let node = pk_from_u8(1);
        sm.register_stake(node, DEFAULT_MIN_STAKE);
        assert_eq!(sm.get_stake(&node), DEFAULT_MIN_STAKE);
        assert!(sm.can_earn(&node));
    }

    #[test]
    fn test_can_earn_with_insufficient_stake() {
        let mut sm = StakeManager::new(DEFAULT_MIN_STAKE);
        let node = pk_from_u8(2);
        sm.register_stake(node, DEFAULT_MIN_STAKE - 1);
        assert!(!sm.can_earn(&node));
        // Top it up to reach the minimum.
        sm.register_stake(node, 1);
        assert!(sm.can_earn(&node));
    }

    #[test]
    fn test_slashing_reduces_stake() {
        let mut sm = StakeManager::new(DEFAULT_MIN_STAKE);
        let node = pk_from_u8(3);
        sm.register_stake(node, 20_000_000_000);
        let slashed = sm.slash(&node, 5_000_000_000);
        assert_eq!(slashed, 5_000_000_000);
        assert_eq!(sm.get_stake(&node), 15_000_000_000);
    }

    #[test]
    fn test_slash_clamped_to_stake() {
        let mut sm = StakeManager::new(DEFAULT_MIN_STAKE);
        let node = pk_from_u8(4);
        sm.register_stake(node, 3_000_000_000);
        // Requesting more than available returns only what's there.
        let slashed = sm.slash(&node, 10_000_000_000);
        assert_eq!(slashed, 3_000_000_000);
        assert_eq!(sm.get_stake(&node), 0);
    }

    #[test]
    fn test_unstake_returns_full_amount() {
        let mut sm = StakeManager::new(DEFAULT_MIN_STAKE);
        let node = pk_from_u8(5);
        sm.register_stake(node, 50_000_000_000);
        let withdrawn = sm.unstake(&node);
        assert_eq!(withdrawn, 50_000_000_000);
        assert_eq!(sm.get_stake(&node), 0);
    }

    // --- TopologicalUniqueness tests ---

    #[test]
    fn test_isolated_node_uniqueness_1() {
        let topo = TopologicalUniqueness::default();
        let node = pk_from_u8(10);
        assert_eq!(topo.uniqueness_score(&node), 1.0);
    }

    #[test]
    fn test_two_colocated_nodes_uniqueness_0_5() {
        let mut topo = TopologicalUniqueness::default();
        let a = pk_from_u8(20);
        let b = pk_from_u8(21);
        // 1 ms latency → below 2 ms threshold.
        topo.record_latency(a, b, 1_000_000);
        topo.record_latency(b, a, 1_000_000);
        assert!((topo.uniqueness_score(&a) - 0.5).abs() < 1e-9);
        assert!((topo.uniqueness_score(&b) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_cluster_of_10_uniqueness_0_1() {
        let mut topo = TopologicalUniqueness::default();
        let nodes: Vec<Pubkey> = (0..10).map(pk_from_u8).collect();
        // Fully connected: every node sees every other at 0.5 ms.
        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    topo.record_latency(nodes[i], nodes[j], 500_000);
                }
            }
        }
        let uniqueness = topo.uniqueness_score(&nodes[0]);
        assert!((uniqueness - 0.1).abs() < 1e-9);
    }

    #[test]
    fn test_farm_detection_cluster_above_10_flagged() {
        let mut topo = TopologicalUniqueness::default();
        let nodes: Vec<Pubkey> = (0..15).map(pk_from_u8).collect();
        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    topo.record_latency(nodes[i], nodes[j], 500_000);
                }
            }
        }
        assert!(topo.flag_farm(&nodes[0]));
    }

    #[test]
    fn test_no_farm_for_small_cluster() {
        let mut topo = TopologicalUniqueness::default();
        let nodes: Vec<Pubkey> = (0..5).map(pk_from_u8).collect();
        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    topo.record_latency(nodes[i], nodes[j], 500_000);
                }
            }
        }
        assert!(!topo.flag_farm(&nodes[0]));
    }

    // --- FarmDetector tests ---

    #[test]
    fn test_reward_multiplier_isolated_full_cluster_reduced() {
        let mut fd = FarmDetector::default();
        let isolated = pk_from_u8(100);
        let clustered_a = pk_from_u8(101);
        let clustered_b = pk_from_u8(102);

        // All meet stake requirement.
        fd.stakes.register_stake(isolated, DEFAULT_MIN_STAKE);
        fd.stakes.register_stake(clustered_a, DEFAULT_MIN_STAKE);
        fd.stakes.register_stake(clustered_b, DEFAULT_MIN_STAKE);

        // Cluster the two.
        fd.topology
            .record_latency(clustered_a, clustered_b, 1_000_000);
        fd.topology
            .record_latency(clustered_b, clustered_a, 1_000_000);

        let iso_assessment = fd.assess_node(&isolated);
        let clu_assessment = fd.assess_node(&clustered_a);

        assert!((iso_assessment.reward_multiplier - 1.0).abs() < 1e-9);
        assert!((clu_assessment.reward_multiplier - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_zero_stake_zero_reward_even_online() {
        let mut fd = FarmDetector::default();
        let node = pk_from_u8(200);
        // No stake registered.
        fd.topology
            .record_latency(node, pk_from_u8(201), 100_000_000);

        let reward = fd.reward_for_node(&node, 1_000_000_000);
        assert_eq!(reward, 0);
    }

    #[test]
    fn test_slash_farm_reduces_all_cluster_members() {
        let mut fd = FarmDetector::default();
        let nodes: Vec<Pubkey> = (0..12).map(pk_from_u8).collect();
        // Register stakes and build a fully-connected cluster.
        for n in &nodes {
            fd.stakes.register_stake(*n, 20_000_000_000);
        }
        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    fd.topology.record_latency(nodes[i], nodes[j], 500_000);
                }
            }
        }

        let cluster = fd.topology.detect_cluster(&nodes[0]);
        let slashed = fd.slash_farm(&cluster);

        // Every cluster member should have been slashed by 50%.
        assert_eq!(slashed.len(), nodes.len());
        for (_, amount) in &slashed {
            assert_eq!(*amount, 10_000_000_000);
        }
        // Verify stakes were actually reduced.
        for n in &nodes {
            assert_eq!(fd.stakes.get_stake(n), 10_000_000_000);
        }
    }

    #[test]
    fn test_reward_for_node_base_reward_calculation() {
        let mut fd = FarmDetector::default();
        let node = pk_from_u8(250);
        fd.stakes.register_stake(node, DEFAULT_MIN_STAKE);
        // Node is isolated → uniqueness 1.0, can_earn true.
        let base: u64 = 5_000_000_000;
        let reward = fd.reward_for_node(&node, base);
        assert_eq!(reward, base);

        // Now add a co-located peer with stake.
        let peer = pk_from_u8(251);
        fd.stakes.register_stake(peer, DEFAULT_MIN_STAKE);
        fd.topology.record_latency(node, peer, 1_000_000);
        fd.topology.record_latency(peer, node, 1_000_000);
        let reward_after = fd.reward_for_node(&node, base);
        assert_eq!(reward_after, base / 2);
    }

    #[test]
    fn test_assess_node_returns_correct_fields() {
        let mut fd = FarmDetector::default();
        let node = pk_from_u8(30);
        fd.stakes.register_stake(node, 15_000_000_000);
        // Isolated node.
        let assessment = fd.assess_node(&node);
        assert_eq!(assessment.node_id, node);
        assert_eq!(assessment.stake, 15_000_000_000);
        assert!((assessment.uniqueness - 1.0).abs() < 1e-9);
        assert!(!assessment.is_farm);
        assert!((assessment.reward_multiplier - 1.0).abs() < 1e-9);
        assert_eq!(assessment.estimated_reward, 1_000_000_000);
    }
}
