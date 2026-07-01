//! Embedded HTTP server with Web UI for EpsilonChat.
//!
//! Serves a single-page app at `/` and JSON API at `/api/*`.
//! Shared state so Alice (forester) and Bob (phone) can interact.

use anyhow::Result;
use axum::{
    extract::State,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

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

/// Shared state — Alice and Bob see the same state
#[derive(Clone, Default)]
pub struct WebState {
    pub mode: String,
    pub alice_running: bool,
    pub bob_running: bool,
    pub connected: bool,
    pub leaves: Vec<LeafInfo>,
    pub proofs_served: u64,
    pub invite_link: Option<String>,
    pub alice_tree: Option<String>,
    pub bob_owner: Option<String>,
}

pub async fn run_web_ui(port: u16) -> Result<()> {
    let state = Arc::new(Mutex::new(WebState::default()));

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
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    println!("╔══════════════════════════════════════════╗");
    println!("║  EpsilonChat Web UI                       ║");
    println!("║  Open: http://localhost:{}              ║", port);
    println!("║  Phone: http://192.168.1.139:{}          ║", port);
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
    Json(json!({
        "alice_running": s.alice_running,
        "bob_running": s.bob_running,
        "connected": s.connected,
        "leaves": s.leaves,
        "proofs_served": s.proofs_served,
        "alice_tree": s.alice_tree,
        "bob_owner": s.bob_owner,
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

    // Simulate fetching leaves from Solana devnet
    s.leaves = vec![
        LeafInfo {
            hash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            owner: "AZGrvCVjwz9DZ2FrbWyDG26rjVvAdLGRX5M7dh2TgaTD".to_string(),
            lamports: 5_000_000,
            index: 0,
        },
        LeafInfo {
            hash: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b200".to_string(),
            owner: "TDPQvCMcE2sKJRZZa4xgt1URZcyszFhwic6mX9bVSfi".to_string(),
            lamports: 12_000_000,
            index: 1,
        },
        LeafInfo {
            hash: "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c300".to_string(),
            owner: "5Hx3Wp7V2mNk8RqL4sJ6dTcF9bX2yZ8aP1wQ3eR5tU7v".to_string(),
            lamports: 750_000,
            index: 2,
        },
    ];

    Json(json!({ "ok": true, "leaves": s.leaves.len(), "message": "Forester started" }))
}

async fn forester_stop(State(state): State<Arc<Mutex<WebState>>>) -> Json<Value> {
    let mut s = state.lock().await;
    s.alice_running = false;
    s.leaves.clear();
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

    Json(json!({
        "ok": true,
        "leaf": leaf,
        "message": if leaf.is_some() { "Phone started, leaf found" } else { "Phone started, no leaf yet" }
    }))
}

async fn phone_stop(State(state): State<Arc<Mutex<WebState>>>) -> Json<Value> {
    let mut s = state.lock().await;
    s.bob_running = false;
    Json(json!({ "ok": true }))
}

async fn phone_proof(State(state): State<Arc<Mutex<WebState>>>) -> Json<Value> {
    let mut s = state.lock().await;

    if !s.connected {
        return Json(json!({ "ok": false, "error": "Not connected to Alice. Go to Mesh tab and connect first." }));
    }
    if !s.alice_running {
        return Json(json!({ "ok": false, "error": "Alice is not running. Start forester first." }));
    }

    s.proofs_served += 1;

    // Find Bob's leaf proof
    let bob_owner = s.bob_owner.clone().unwrap_or_default();
    let leaf = s.leaves.iter().find(|l| l.owner == bob_owner).cloned();

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
    let invite = json!({
        "id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "addrs": [
            {"Ip": "192.168.1.139:61897"},
            {"Ip": "[2a02:2f0f:b00c:2400:87f:f056:ea13:c33b]:61794"}
        ]
    }).to_string();
    s.invite_link = Some(invite.clone());
    Json(json!({ "ok": true, "invite": invite }))
}

#[derive(Deserialize)]
struct ConnectReq {
    link: String,
}

async fn mesh_connect(
    State(state): State<Arc<Mutex<WebState>>>,
    Json(_req): Json<ConnectReq>,
) -> Json<Value> {
    let mut s = state.lock().await;
    s.connected = true;
    Json(json!({ "ok": true, "peer_id": "alice-forester-001" }))
}

async fn mesh_disconnect(State(state): State<Arc<Mutex<WebState>>>) -> Json<Value> {
    let mut s = state.lock().await;
    s.connected = false;
    Json(json!({ "ok": true }))
}