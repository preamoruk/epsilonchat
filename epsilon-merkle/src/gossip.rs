//! Iroh gossip layer — broadcast leaf updates + invite links.
//!
//! Uses Iroh gossip to broadcast LeafEntry updates to all peers.
//! Uses Iroh endpoint for invite link generation and connection.
//! RelayMode::Disabled — pure P2P, no external infrastructure.

use anyhow::Result;
use iroh::Endpoint;
use iroh::endpoint::presets::N0;
use iroh::endpoint::RelayMode;
use serde::{Deserialize, Serialize};

/// ALPN protocol identifier for epsilon merkle gossip
pub const EPSILON_ALPN: &[u8] = b"epsilon/merkle/1";

/// Gossip message types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipMessage {
    /// New or updated leaf (broadcast by forester)
    LeafUpdate {
        leaf_hash: [u8; 32],
        leaf_index: u64,
        merkle_tree: [u8; 32],
        owner: [u8; 32],
        lamports: u64,
        root: [u8; 32],
        root_seq: u64,
        slot: u64,
    },
    /// Proof request (phone asks forester for a proof)
    ProofRequest {
        merkle_tree: [u8; 32],
        leaf_index: u64,
    },
    /// Proof response (forester replies to phone)
    ProofResponse {
        leaf: [u8; 32],
        leaf_index: u64,
        merkle_tree: [u8; 32],
        proof: Vec<[u8; 32]>,
        root: [u8; 32],
        root_seq: u64,
    },
    /// Heartbeat (peer announces presence)
    Heartbeat {
        is_forester: bool,
        leaf_count: u64,
    },
}

impl GossipMessage {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}

/// Create an Iroh endpoint with relay and address lookup disabled (pure P2P, no external infra)
fn endpoint_builder() -> iroh::endpoint::Builder {
    Endpoint::builder(N0)
        .alpns(vec![EPSILON_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
}

/// Generate an Iroh invite link for peer connection
pub async fn generate_invite() -> Result<()> {
    let endpoint = endpoint_builder().bind().await?;

    let addr = endpoint.addr();
    let ticket_json = serde_json::to_string(&addr)?;

    println!("\n=== EpsilonChat Invite Link ===");
    println!("{}", ticket_json);
    println!("================================\n");
    println!("Share this with another peer (any channel: Telegram, SMS, etc.)");
    println!("They run: epsilon-merkle connect \"<link>\"\n");

    // Keep endpoint alive for 60 seconds so peers can connect
    println!("Endpoint listening for 60 seconds...");
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    println!("Endpoint shutting down.");
    Ok(())
}

/// Connect to a peer via invite link
pub async fn connect_via_invite(link: &str) -> Result<()> {
    let addr: iroh_base::EndpointAddr = serde_json::from_str(link)?;

    let endpoint = endpoint_builder().bind().await?;

    println!("Connecting to peer (direct, no relay)...");
    let conn = endpoint.connect(addr, EPSILON_ALPN).await?;
    println!("Connected to: {}", conn.remote_id());
    println!("Connection established successfully!");

    // Keep alive for 30 seconds
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    println!("Disconnecting.");
    Ok(())
}

/// Create an Iroh endpoint for the gossip protocol
pub async fn create_endpoint(_data_dir: &str) -> Result<Endpoint> {
    let endpoint = endpoint_builder().bind().await?;
    tracing::info!("Iroh endpoint created: id={}", endpoint.id());
    Ok(endpoint)
}