//! EpsilonChat — Mesh-stored Merkle tree for Solana ZK Compression
//!
//! Replaces centralized Photon Indexer with P2P mesh distribution
//! of Merkle tree leaves via Iroh gossip + DHT.

pub mod android_bridge;
pub mod anti_farm;
pub mod availability;
pub mod chat_core;
pub mod ffi;
pub mod gossip;
pub mod leaf_store;
pub mod mesh_indexer;
pub mod payment;
pub mod proof_provider;
pub mod proof_requester;
pub mod solana_zk;
pub mod token_account;
pub mod tree_replica;
pub mod validator;
pub mod vrf_sortition;
pub mod web_ui;