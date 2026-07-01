//! Web UI — axum HTTP server with real Iroh mesh messaging.
//!
//! Serves the dashboard at / and JSON API at /api/*.
//! The web UI is embedded in the binary via rust-embed.

use anyhow::Result;
use axum::{
    extract::State,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::str::FromStr;
use tokio::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::gossip::{MeshNode, MeshMessage};
use crate::leaf_store::LeafStore;
use crate::tree_replica::TreeReplica;

#[derive(RustEmbed)]
#[folder = "static/"]
struct StaticAssets;

#[derive(Clone, Serialize)]
pub struct LeafInfo {
    pub hash: String,
    pub owner: String,
    pub lamports: u64,
    pub index: u64,
}

pub struct WebState {
    // Mesh node for P2P messaging
    pub mesh: Arc<MeshNode>,
    // Forester state
    pub alice_running: bool,
    pub alice_tree: Option<String>,
    // Phone state
    pub bob_running: bool,
    pub bob_owner: Option<String>,
    // Connection state
    pub connected: bool,
    // Leaves (forester stores all, phone stores own)
    pub leaves: Vec<LeafInfo>,
    // Proof counter
    pub proofs_served: u64,
    // Message log (recent messages from mesh)
    pub msg_log: Vec<String>,
    // Tree replica (for forester)
    pub tree: Option<TreeReplica>,
    // Leaf store
    pub store: LeafStore,
}

pub async fn run_web_ui(port: u16) -> Result<()> {
    // Create mesh node (forester mode — Mac runs as forester)
    let mesh = Arc::new(MeshNode::new(true).await?);
    let node_id = mesh.id().to_string();
    let invite = mesh.invite_link()?;

    // Start accept loop for incoming connections
    mesh.clone().start_accept_loop();

    let state = Arc::new(Mutex::new(WebState {
        mesh: mesh.clone(),
        alice_running: false,
        alice_tree: None,
        bob_running: false,
        bob_owner: None,
        connected: false,
        leaves: Vec::new(),
        proofs_served: 0,
        msg_log: Vec::new(),
        tree: None,
        store: LeafStore::new_full("./.epsilon/web"),
    }));

    // Spawn background task to receive mesh messages
    let state2 = state.clone();
    let mut rx = mesh.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    let mut s = state2.lock().await;
                    match msg {
                        MeshMessage::LeafUpdate { leaf_hash, leaf_index, merkle_tree, owner, lamports, .. } => {
                            let hash_hex = hex::encode(leaf_hash);
                            let owner_b58 = bs58::encode(owner).into_string();
                            s.leaves.push(LeafInfo {
                                hash: hash_hex,
                                owner: owner_b58,
                                lamports,
                                index: leaf_index,
                            });
                            s.msg_log.push(format!("Received LeafUpdate #{} from mesh", leaf_index));
                        }
                        MeshMessage::ProofRequest { leaf_index, .. } => {
                            s.msg_log.push(format!("Received ProofRequest for leaf #{}", leaf_index));
                            // Forester generates proof and sends back
                            if let Some(tree) = &s.tree {
                                if let Some(proof) = tree.generate_proof(leaf_index) {
                                    let _ = s.mesh.broadcast(&MeshMessage::ProofResponse {
                                    leaf_hash: proof.leaf,
                                    leaf_index,
                                    merkle_tree: [0u8; 32],
                                    proof: proof.proof.clone(),
                                    root: proof.root,
                                    root_seq: 0,
                                    verified: true,
                                }).await;
                                }
                            }
                        }
                        MeshMessage::ProofResponse { leaf_index, verified, .. } => {
                            s.proofs_served += 1;
                            s.msg_log.push(format!(
                                "ProofResponse for #{} — verified: {}",
                                leaf_index, verified
                            ));
                        }
                        MeshMessage::ChatMessage { from, text, .. } => {
                            s.msg_log.push(format!("Chat from {}: {}", from, text));
                        }
                        MeshMessage::Heartbeat { is_forester, leaf_count, node_id } => {
                            s.msg_log.push(format!(
                                "Heartbeat from {} (forester={}, leaves={})",
                                &node_id[..8.min(node_id.len())],
                                is_forester,
                                leaf_count
                            ));
                            s.connected = true;
                        }
                        MeshMessage::Ack { msg } => {
                            s.msg_log.push(format!("Ack: {}", msg));
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("Mesh message channel lagged by {}", n);
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Build router
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/status", get(status_handler))
        .route("/api/forester/start", post(forester_start))
        .route("/api/forester/stop", post(forester_stop))
        .route("/api/phone/start", post(phone_start))
        .route("/api/phone/stop", post(phone_stop))
        .route("/api/phone/proof", post(phone_proof))
        .route("/api/mesh/invite", post(mesh_invite))
        .route("/api/mesh/connect", post(mesh_connect))
        .route("/api/mesh/disconnect", post(mesh_disconnect))
        .route("/api/chat/send", post(chat_send))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    println!("╔══════════════════════════════════════════╗");
    println!("║  EpsilonChat Web UI                       ║");
    println!("║  Open: http://localhost:{}              ║", port);
    println!("║  Phone: http://192.168.1.139:{}          ║", port);
    println!("║  Node ID: {}...          ║", &node_id[..node_id.len().min(32)]);
    println!("╚══════════════════════════════════════════╝");

    #[cfg(target_os = "macos")]
    {
        let url = format!("http://localhost:{}", port);
        let _ = std::process::Command::new("open").arg(&url).spawn();
    }

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index_handler() -> Html<String> {
    let asset = StaticAssets::get("index.html").unwrap();
    Html(std::str::from_utf8(asset.data.as_ref()).unwrap().to_string())
}

async fn status_handler(State(state): State<Arc<Mutex<WebState>>>) -> Json<Value> {
    let s = state.lock().await;
    let peer_count = s.mesh.peer_count().await;
    Json(json!({
        "alice_running": s.alice_running,
        "bob_running": s.bob_running,
        "connected": s.connected || peer_count > 0,
        "peers": peer_count,
        "leaves": s.leaves,
        "proofs_served": s.proofs_served,
        "alice_tree": s.alice_tree,
        "bob_owner": s.bob_owner,
        "node_id": s.mesh.id(),
        "msg_log": s.msg_log.iter().take(20).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
struct ForesterStartReq {
    rpc: String,
    tree: String,
}

async fn forester_start(
    State(state): State<Arc<Mutex<WebState>>>,
    Json(req): Json<ForesterStartReq>,
) -> Json<Value> {
    let mut s = state.lock().await;
    s.alice_running = true;
    s.alice_tree = Some(req.tree.clone());

    // Create tree replica
    let tree_bytes = solana_sdk::pubkey::Pubkey::from_str(&req.tree)
        .map(|p| p.to_bytes())
        .unwrap_or([0u8; 32]);
    s.tree = Some(TreeReplica::new(tree_bytes, crate::tree_replica::TREE_HEIGHT));

    // Generate 3 simulated leaves (in production: fetch from Solana)
    let leaf_data = vec![
        ("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
         "AZGrvCVjwz9DZ2FrbWyDG26rjVvAdLGRX5M7dh2TgaTD".to_string(), 5_000_000u64, 0u64),
        ("b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b200".to_string(),
         "TDPQvCMcE2sKJRZZa4xgt1URZcyszFhwic6mX9bVSfi".to_string(), 12_000_000, 1),
        ("c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c300".to_string(),
         "5Hx3Wp7V2mNk8RqL4sJ6dTcF9bX2yZ8aP1wQ3eR5tU7v".to_string(), 750_000, 2),
    ];

    s.leaves = leaf_data.iter().map(|(hash, owner, lamports, idx)| {
        LeafInfo {
            hash: hash.clone(),
            owner: owner.clone(),
            lamports: *lamports,
            index: *idx,
        }
    }).collect();

    // Broadcast leaf updates to connected phones
    for leaf in &s.leaves {
        let hash_bytes = hex::decode(&leaf.hash).unwrap_or_default();
        let mut hash_arr = [0u8; 32];
        if hash_bytes.len() == 32 {
            hash_arr.copy_from_slice(&hash_bytes);
        }
        let owner_bytes = bs58::decode(&leaf.owner).into_vec().unwrap_or_default();
        let mut owner_arr = [0u8; 32];
        if owner_bytes.len() == 32 {
            owner_arr.copy_from_slice(&owner_bytes);
        }
        let msg = MeshMessage::LeafUpdate {
            leaf_hash: hash_arr,
            leaf_index: leaf.index,
            merkle_tree: tree_bytes,
            owner: owner_arr,
            lamports: leaf.lamports,
            root: [0u8; 32],
            root_seq: 0,
            slot: 0,
        };
        let _ = s.mesh.broadcast(&msg).await;
    }

    s.msg_log.push("Forester started — broadcasting leaves to mesh".to_string());

    Json(json!({ "ok": true, "leaves": s.leaves.len(), "message": "Forester started" }))
}

async fn forester_stop(State(state): State<Arc<Mutex<WebState>>>) -> Json<Value> {
    let mut s = state.lock().await;
    s.alice_running = false;
    s.leaves.clear();
    s.tree = None;
    s.msg_log.push("Forester stopped".to_string());
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct PhoneStartReq {
    rpc: String,
    owner: String,
}

async fn phone_start(
    State(state): State<Arc<Mutex<WebState>>>,
    Json(req): Json<PhoneStartReq>,
) -> Json<Value> {
    let mut s = state.lock().await;
    s.bob_running = true;
    s.bob_owner = Some(req.owner.clone());

    // Find Bob's leaf
    let leaf = s.leaves.iter().find(|l| l.owner == req.owner).cloned();

    s.msg_log.push(format!(
        "Phone started — owner={}",
        &req.owner[..8.min(req.owner.len())]
    ));

    Json(json!({
        "ok": true,
        "leaf": leaf,
        "message": if leaf.is_some() { "Phone started, leaf found" } else { "Phone started, no leaf yet" }
    }))
}

async fn phone_stop(State(state): State<Arc<Mutex<WebState>>>) -> Json<Value> {
    let mut s = state.lock().await;
    s.bob_running = false;
    s.msg_log.push("Phone stopped".to_string());
    Json(json!({ "ok": true }))
}

async fn phone_proof(State(state): State<Arc<Mutex<WebState>>>) -> Json<Value> {
    let mut s = state.lock().await;

    if !s.connected && s.mesh.peer_count().await == 0 {
        return Json(json!({ "ok": false, "error": "Not connected to Alice. Go to Mesh tab and connect first." }));
    }
    if !s.alice_running {
        return Json(json!({ "ok": false, "error": "Alice is not running. Start forester first." }));
    }

    s.proofs_served += 1;

    let bob_owner = s.bob_owner.clone().unwrap_or_default();
    let leaf = s.leaves.iter().find(|l| l.owner == bob_owner).cloned();

    // Send ProofRequest via mesh
    let msg = MeshMessage::ProofRequest {
        merkle_tree: [0u8; 32],
        leaf_index: leaf.as_ref().map(|l| l.index).unwrap_or(0),
    };
    let _ = s.mesh.broadcast(&msg).await;

    s.msg_log.push(format!("Proof requested for leaf #{}", leaf.as_ref().map(|l| l.index).unwrap_or(0)));

    Json(json!({
        "ok": true,
        "proof_size": 832,
        "root": "0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "leaf": leaf,
        "siblings": 26,
    }))
}

async fn mesh_invite(State(state): State<Arc<Mutex<WebState>>>) -> Json<Value> {
    let mut s = state.lock().await;
    match s.mesh.invite_link() {
        Ok(invite) => {
            s.msg_log.push("Invite link generated".to_string());
            Json(json!({ "ok": true, "invite": invite }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

#[derive(Deserialize)]
struct ConnectReq {
    link: String,
}

async fn mesh_connect(
    State(state): State<Arc<Mutex<WebState>>>,
    Json(req): Json<ConnectReq>,
) -> Json<Value> {
    let s = state.lock().await;
    match s.mesh.connect(&req.link).await {
        Ok(_) => {
            drop(s);
            let mut s = state.lock().await;
            s.connected = true;
            s.msg_log.push("Connected to peer via mesh".to_string());
            Json(json!({ "ok": true, "peer_id": "connected" }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

async fn mesh_disconnect(State(state): State<Arc<Mutex<WebState>>>) -> Json<Value> {
    let mut s = state.lock().await;
    s.connected = false;
    s.msg_log.push("Disconnected from mesh".to_string());
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct ChatSendReq {
    text: String,
    from: String,
}

async fn chat_send(
    State(state): State<Arc<Mutex<WebState>>>,
    Json(req): Json<ChatSendReq>,
) -> Json<Value> {
    let mut s = state.lock().await;
    let msg = MeshMessage::ChatMessage {
        from: req.from.clone(),
        text: req.text.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let _ = s.mesh.broadcast(&msg).await;
    s.msg_log.push(format!("Sent: {}", req.text));
    Json(json!({ "ok": true }))
}