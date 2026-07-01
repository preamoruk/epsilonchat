//! Iroh mesh messaging layer — real P2P message passing between devices.
//!
//! Alice (forester) and Bob (phone) exchange messages over Iroh QUIC streams:
//! - LeafUpdate: forester broadcasts new leaves to connected phones
//! - ProofRequest: phone asks forester for a Merkle proof
//! - ProofResponse: forester sends back the proof
//! - ChatMessage: ephemeral text messages between peers
//! - Heartbeat: peer presence announcements

use anyhow::{Context, Result};
use iroh::endpoint::presets::N0;
use iroh::endpoint::RelayMode;
use iroh::Endpoint;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

/// ALPN protocol identifier for epsilon mesh
pub const EPSILON_ALPN: &[u8] = b"epsilon/mesh/1";

/// Maximum message size (1 MB)
const MAX_MSG_SIZE: usize = 1024 * 1024;

/// Mesh message types exchanged between peers over Iroh streams
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MeshMessage {
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
    ProofRequest {
        merkle_tree: [u8; 32],
        leaf_index: u64,
    },
    ProofResponse {
        leaf_hash: [u8; 32],
        leaf_index: u64,
        merkle_tree: [u8; 32],
        proof: Vec<[u8; 32]>,
        root: [u8; 32],
        root_seq: u64,
        verified: bool,
    },
    ChatMessage {
        from: String,
        text: String,
        timestamp: u64,
    },
    Heartbeat {
        is_forester: bool,
        leaf_count: u64,
        node_id: String,
    },
    Ack {
        msg: String,
    },
}

impl MeshMessage {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}

/// Track a connected peer and its connection
#[derive(Clone)]
pub struct PeerConnection {
    pub node_id: String,
    pub is_forester: bool,
    pub conn: iroh::endpoint::Connection,
    pub last_seen: std::time::Instant,
}

/// How long without hearing from a peer before we consider them dead
const PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Heartbeat broadcast interval
const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// The mesh node — wraps an Iroh Endpoint with message handling
pub struct MeshNode {
    endpoint: Endpoint,
    pub msg_tx: broadcast::Sender<MeshMessage>,
    pub peers: Arc<Mutex<Vec<PeerConnection>>>,
    pub node_id: String,
    pub is_forester: bool,
}

impl MeshNode {
    /// Create a new mesh node (forester or phone)
    pub async fn new(is_forester: bool) -> Result<Self> {
        let endpoint: Endpoint = Endpoint::builder(N0)
            .alpns(vec![EPSILON_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind()
            .await?;

        let node_id = endpoint.id().to_string();
        let (msg_tx, _msg_rx) = broadcast::channel::<MeshMessage>(256);

        tracing::info!(
            "Mesh node created: id={}, forester={}",
            node_id,
            is_forester
        );

        Ok(Self {
            endpoint,
            msg_tx,
            peers: Arc::new(Mutex::new(Vec::new())),
            node_id,
            is_forester,
        })
    }

    /// Get the endpoint address for generating invite links
    pub fn addr(&self) -> iroh_base::EndpointAddr {
        self.endpoint.addr()
    }

    /// Get our node ID
    pub fn id(&self) -> &str {
        &self.node_id
    }

    /// Generate an invite link
    pub fn invite_link(&self) -> Result<String> {
        let addr = self.addr();
        Ok(serde_json::to_string(&addr)?)
    }

    /// Connect to a peer via invite link
    pub async fn connect(&self, link: &str) -> Result<String> {
        let addr: iroh_base::EndpointAddr =
            serde_json::from_str(link).context("Invalid invite link format")?;

        tracing::info!("Connecting to peer...");
        let conn = self.endpoint.connect(addr, EPSILON_ALPN).await?;
        let remote_id = conn.remote_id().to_string();
        tracing::info!("Connected to: {}", remote_id);

        let peer_conn = PeerConnection {
            node_id: remote_id.clone(),
            is_forester: !self.is_forester,
            conn: conn.clone(),
            last_seen: std::time::Instant::now(),
        };

        self.peers.lock().await.push(peer_conn);

        // Start receive loop for this connection
        let msg_tx = self.msg_tx.clone();
        let peers = self.peers.clone();
        let rid = remote_id.clone();
        tokio::spawn(async move {
            receive_loop(conn, msg_tx, peers, rid).await;
        });

        Ok(remote_id)
    }

    /// Send a message to all connected peers via uni streams
    pub async fn broadcast(&self, msg: &MeshMessage) -> Result<()> {
        let data = msg.encode();
        let peers = self.peers.lock().await;
        let mut sent = 0;
        for peer in peers.iter() {
            match peer.conn.open_uni().await {
                Ok(mut send) => {
                    use tokio::io::AsyncWriteExt;
                    send.write_all(&data).await?;
                    send.finish()?;
                    sent += 1;
                }
                Err(e) => {
                    tracing::warn!("Failed to send to {}: {}", peer.node_id, e);
                }
            }
        }
        tracing::debug!("Broadcasted message to {} peers", sent);
        Ok(())
    }

    /// Start the accept loop — listens for incoming connections
    pub fn start_accept_loop(self: Arc<Self>) {
        let msg_tx = self.msg_tx.clone();
        let peers = self.peers.clone();
        let is_forester = self.is_forester;

        tokio::spawn(async move {
            loop {
                // endpoint.accept() returns a Future<Output=Option<Incoming>>
                let incoming = match self.endpoint.accept().await {
                    Some(incoming) => incoming,
                    None => break,
                };

                // Accept the incoming connection
                let accepting = match incoming.accept() {
                    Ok(accepting) => accepting,
                    Err(e) => {
                        tracing::warn!("Failed to accept connection: {}", e);
                        continue;
                    }
                };

                // Wait for the connection to complete
                let conn = match accepting.await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!("Connection failed: {}", e);
                        continue;
                    }
                };

                let remote_id = conn.remote_id().to_string();
                tracing::info!("Peer connected: {}", remote_id);

                peers.lock().await.push(PeerConnection {
                    node_id: remote_id.clone(),
                    is_forester: !is_forester,
                    conn: conn.clone(),
                    last_seen: std::time::Instant::now(),
                });

                let msg_tx2 = msg_tx.clone();
                let peers2 = peers.clone();
                let rid = remote_id.clone();
                tokio::spawn(async move {
                    receive_loop(conn, msg_tx2, peers2, rid).await;
                });
            }
        });
    }

    /// Get number of connected peers (prunes dead peers first)
    pub async fn peer_count(&self) -> usize {
        self.prune_dead_peers().await;
        self.peers.lock().await.len()
    }

    /// Remove peers that haven't been heard from in PEER_TIMEOUT or whose connection is closed
    pub async fn prune_dead_peers(&self) {
        let now = std::time::Instant::now;
        let mut peers = self.peers.lock().await;
        peers.retain(|p| {
            let alive = now().duration_since(p.last_seen) < PEER_TIMEOUT
                && p.conn.close_reason().is_none();
            if !alive {
                tracing::info!("Pruning dead peer: {}", p.node_id);
            }
            alive
        });
    }

    /// Start heartbeat sender + peer sweeper background task
    pub fn start_heartbeat(self: Arc<Self>) {
        let node = self.clone();
        let peers = self.peers.clone();
        let is_forester = self.is_forester;
        let node_id = self.node_id.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEARTBEAT_INTERVAL).await;

                // Prune dead peers
                let now = std::time::Instant::now;
                {
                    let mut p = peers.lock().await;
                    p.retain(|peer| {
                        let alive = now().duration_since(peer.last_seen) < PEER_TIMEOUT
                            && peer.conn.close_reason().is_none();
                        if !alive {
                            tracing::info!("Sweeper pruned dead peer: {}", peer.node_id);
                        }
                        alive
                    });
                }

                // Broadcast heartbeat to all peers
                let leaf_count = peers.lock().await.len() as u64;
                let msg = MeshMessage::Heartbeat {
                    is_forester,
                    leaf_count,
                    node_id: node_id.clone(),
                };
                let _ = node.broadcast(&msg).await;
            }
        });
    }

    /// Get connected peer IDs
    pub async fn peer_ids(&self) -> Vec<String> {
        self.peers
            .lock()
            .await
            .iter()
            .map(|p| p.node_id.clone())
            .collect()
    }

    /// Subscribe to incoming messages
    pub fn subscribe(&self) -> broadcast::Receiver<MeshMessage> {
        self.msg_tx.subscribe()
    }
}

/// Background task: receive messages from a connected peer via uni streams
async fn receive_loop(
    conn: iroh::endpoint::Connection,
    msg_tx: broadcast::Sender<MeshMessage>,
    peers: Arc<Mutex<Vec<PeerConnection>>>,
    remote_id: String,
) {
    loop {
        match conn.accept_uni().await {
            Ok(mut recv) => {
                // Read the full message
                match recv.read_to_end(MAX_MSG_SIZE).await {
                    Ok(data) => {
                        if !data.is_empty() {
                            // Update last_seen for this peer
                            {
                                let mut p = peers.lock().await;
                                for peer in p.iter_mut() {
                                    if peer.node_id == remote_id {
                                        peer.last_seen = std::time::Instant::now();
                                        break;
                                    }
                                }
                            }
                            if let Some(msg) = MeshMessage::decode(&data) {
                                tracing::debug!(
                                    "Received message from {}: {:?}",
                                    remote_id,
                                    std::mem::discriminant(&msg)
                                );
                                let _ = msg_tx.send(msg);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Read error from {}: {}", remote_id, e);
                    }
                }
            }
            Err(e) => {
                tracing::info!("Peer {} disconnected: {}", remote_id, e);
                peers.lock().await.retain(|p| p.node_id != remote_id);
                break;
            }
        }
    }
}

/// Generate an Iroh invite link for peer connection (CLI)
pub async fn generate_invite() -> Result<()> {
    let node = MeshNode::new(true).await?;
    let link = node.invite_link()?;

    println!("\n=== EpsilonChat Invite Link ===");
    println!("{}", link);
    println!("================================\n");
    println!("Share this with another peer (any channel: Telegram, SMS, etc.)");
    println!("They run: epsilon-merkle connect \"<link>\"\n");

    let node = Arc::new(node);
    node.clone().start_accept_loop();

    println!("Endpoint listening for 60 seconds...");
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    println!("Endpoint shutting down.");
    Ok(())
}

/// Connect to a peer via invite link (CLI)
pub async fn connect_via_invite(link: &str) -> Result<()> {
    let node = MeshNode::new(false).await?;
    let node = Arc::new(node);
    node.clone().start_accept_loop();

    node.connect(link).await?;

    println!("Connected! Listening for messages for 30 seconds...");
    let mut rx = node.subscribe();
    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
            println!("Timeout — disconnecting.");
        }
        msg = rx.recv() => {
            if let Ok(msg) = msg {
                println!("Received message: {:?}", msg);
            }
        }
    }
    Ok(())
}

/// Create an Iroh endpoint (compatibility with old API)
pub async fn create_endpoint(_data_dir: &str) -> Result<Endpoint> {
    let endpoint = Endpoint::builder(N0)
        .alpns(vec![EPSILON_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .bind()
        .await?;
    tracing::info!("Iroh endpoint created: id={}", endpoint.id());
    Ok(endpoint)
}
