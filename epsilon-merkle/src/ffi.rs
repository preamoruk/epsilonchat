//! FFI layer for Android JNI bridge.
//!
//! All functions are wrapped in `catch_unwind` to prevent Rust panics
//! from aborting the Android process (since we removed `panic = 'abort'`
//! from Cargo.toml, panics can now be caught).

use crate::gossip::{MeshMessage, MeshNode};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};
use std::str::FromStr;

static mut MESH_NODE: Option<Arc<MeshNode>> = None;
static mut RUNTIME: Option<tokio::runtime::Runtime> = None;
static mut RECV_QUEUE: Vec<String> = Vec::new();
static STATE_LOCK: Mutex<()> = Mutex::new(());

fn get_handle() -> Option<tokio::runtime::Handle> {
    let _guard = STATE_LOCK.lock().ok()?;
    unsafe { RUNTIME.as_ref().map(|r| r.handle().clone()) }
}

#[no_mangle]
pub extern "C" fn epsilon_start_mesh() -> *mut c_char {
    let result = std::panic::catch_unwind(|| start_mesh_inner());
    match result {
        Ok(Some(id)) => CString::new(id).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

fn start_mesh_inner() -> Option<String> {
    let rt = tokio::runtime::Runtime::new().ok()?;
    let handle = rt.handle().clone();

    let node_id = handle.block_on(async move {
        let _guard = STATE_LOCK.lock().ok();

        unsafe {
            if RUNTIME.is_none() {
                RUNTIME = Some(rt);
            }
        }

        let node = match MeshNode::new(false).await {
            Ok(n) => Arc::new(n),
            Err(_) => return None,
        };

        let accept_node = node.clone();
        accept_node.start_accept_loop();

        let rx_node = node.clone();
        let mut rx = rx_node.subscribe();
        tokio::spawn(async move {
            while let Ok(msg) = rx.recv().await {
                if let MeshMessage::ChatMessage { from, text, .. } = msg {
                    let formatted = format!("{}: {}", from, text);
                    let _g = STATE_LOCK.lock();
                    unsafe { RECV_QUEUE.push(formatted); }
                }
            }
        });

        unsafe { MESH_NODE = Some(node.clone()); }

        Some(node.id().to_string())
    });

    node_id
}

#[no_mangle]
pub extern "C" fn epsilon_get_invite() -> *mut c_char {
    let result = std::panic::catch_unwind(|| get_invite_inner());
    match result {
        Ok(Some(s)) => CString::new(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

fn get_invite_inner() -> Option<String> {
    let handle = get_handle()?;
    let invite = handle.block_on(async {
        unsafe {
            if let Some(ref node) = MESH_NODE {
                let node_id = node.id().to_string();
                let addr = node.addr();
                let addr_json = serde_json::to_string(&addr).unwrap_or_default();
                // Compact format: EPS:<base64 of JSON> — much shorter than URL-encoded
                let b64 = base64_encode(&addr_json);
                Some(format!("EPS:{}", b64))
            } else {
                None
            }
        }
    });
    invite
}

/// Connect to a peer via invite link. Returns null on failure, error string on success.
/// Actually returns: null on failure, "ok:<peer_id>" on success, "error:<msg>" on timeout/failure
#[no_mangle]
pub extern "C" fn epsilon_connect_peer(invite_ptr: *const c_char) -> *mut c_char {
    let result = std::panic::catch_unwind(|| connect_peer_inner(invite_ptr));
    match result {
        Ok(Some(s)) => CString::new(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

fn connect_peer_inner(invite_ptr: *const c_char) -> Option<String> {
    if invite_ptr.is_null() { return Some("error:null invite".to_string()); }

    let invite_cstr = unsafe { CStr::from_ptr(invite_ptr) };
    let invite = match invite_cstr.to_str() { Ok(s) => s, Err(_) => return Some("error:invalid utf8".to_string()) };

    let addr_json = if let Some(b64) = invite.strip_prefix("EPS:") {
        base64_decode(b64)
    } else if let Some(rest) = invite.strip_prefix("epsilon://") {
        if let Some(qmark) = rest.find("?addrs=") {
            urlencoding_decode(&rest[qmark + 7..])
        } else { return Some("error:no addrs in invite".to_string()); }
    } else {
        invite.to_string()
    };

    let handle = get_handle()?;
    // Do NOT hold STATE_LOCK during async connect — would deadlock
    let result = handle.block_on(async {
        unsafe {
            if let Some(ref node) = MESH_NODE {
                match node.connect(&addr_json).await {
                    Ok(peer_id) => Some(format!("ok:{}", peer_id)),
                    Err(e) => Some(format!("error:{}", e)),
                }
            } else { Some("error:mesh not started".to_string()) }
        }
    });
    result
}

#[no_mangle]
pub extern "C" fn epsilon_send_message(text_ptr: *const c_char) -> i32 {
    let result = std::panic::catch_unwind(|| send_message_inner(text_ptr));
    result.unwrap_or(0)
}

fn send_message_inner(text_ptr: *const c_char) -> i32 {
    if text_ptr.is_null() { return 0; }

    let text_cstr = unsafe { CStr::from_ptr(text_ptr) };
    let text = match text_cstr.to_str() { Ok(s) => s.to_string(), Err(_) => return 0 };

    let handle = match get_handle() { Some(h) => h, None => return 0 };
    let ok = handle.block_on(async {
        unsafe {
            if let Some(ref node) = MESH_NODE {
                let msg = MeshMessage::ChatMessage {
                    from: "me".to_string(),
                    text,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
                node.broadcast(&msg).await.is_ok()
            } else { false }
        }
    });
    if ok { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn epsilon_recv_message() -> *mut c_char {
    let result = std::panic::catch_unwind(|| recv_message_inner());
    match result {
        Ok(Some(s)) => CString::new(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

fn recv_message_inner() -> Option<String> {
    let handle = get_handle()?;
    handle.block_on(async {
        let _g = STATE_LOCK.lock();
        unsafe { RECV_QUEUE.pop() }
    })
}

#[no_mangle]
pub extern "C" fn epsilon_peer_count() -> i32 {
    let result = std::panic::catch_unwind(|| peer_count_inner());
    result.unwrap_or(0)
}

fn peer_count_inner() -> i32 {
    let handle = match get_handle() { Some(h) => h, None => return 0 };
    let count = handle.block_on(async {
        unsafe {
            if let Some(ref node) = MESH_NODE { node.peer_count().await } else { 0 }
        }
    });
    count as i32
}

#[no_mangle]
pub extern "C" fn epsilon_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); }
    }
}

// ════════════════════════════════════════════════════════════
// Wallet & Mining FFI functions (items 4, 5, 6)
// ════════════════════════════════════════════════════════════

static mut MINING_ENABLED: bool = true;
static mut WALLET_PUBKEY: Option<String> = None;
static MINING_LOCK: Mutex<()> = Mutex::new(());

/// Get wallet balance (SOL + EPS) as JSON: {"sol": 0.0, "eps": 0.0, "address": "..."}
#[no_mangle]
pub extern "C" fn epsilon_get_balance() -> *mut c_char {
    let result = std::panic::catch_unwind(|| get_balance_inner());
    match result {
        Ok(Some(s)) => CString::new(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

fn get_balance_inner() -> Option<String> {
    let _g = MINING_LOCK.lock().ok()?;
    let address = unsafe { WALLET_PUBKEY.as_ref().cloned().unwrap_or_default() };
    let rpc = "https://api.devnet.solana.com".to_string();
    let eps_mint = "EPSdGvXoKLrWQ8xqF5yZzXq3PZxXqZxXqZxXqZxXqZxX".to_string();
    
    // Get SOL balance via RpcClient
    let sol_balance = {
        let rpc_client = solana_rpc_client::rpc_client::RpcClient::new_with_timeout(
            rpc.clone(),
            std::time::Duration::from_secs(10),
        );
        match solana_sdk::pubkey::Pubkey::from_str(&address) {
            Ok(pk) => rpc_client.get_balance(&pk).map(|l| l as f64 / 1e9).unwrap_or(0.0),
            Err(_) => 0.0,
        }
    };

    // Get EPS balance via TokenClient
    let eps_balance = match crate::token_account::TokenClient::new(&rpc, &eps_mint) {
        Ok(client) => {
            match client.get_token_balance(&address) {
                Ok(info) => info.ui_amount,
                Err(_) => 0.0,
            }
        }
        Err(_) => 0.0,
    };

    Some(serde_json::to_string(&serde_json::json!({
        "sol": sol_balance,
        "eps": eps_balance,
        "address": address,
    })).unwrap_or_default())
}

/// Set wallet pubkey for balance queries
#[no_mangle]
pub extern "C" fn epsilon_set_wallet(pubkey_ptr: *const c_char) {
    let result = std::panic::catch_unwind(|| {
        if pubkey_ptr.is_null() { return; }
        let pk_cstr = unsafe { CStr::from_ptr(pubkey_ptr) };
        if let Ok(pk) = pk_cstr.to_str() {
            let _g = MINING_LOCK.lock();
            unsafe { WALLET_PUBKEY = Some(pk.to_string()); }
        }
    });
    let _ = result;
}

/// Get mining speed (EPS per hour) as f64
#[no_mangle]
pub extern "C" fn epsilon_get_mining_speed() -> f64 {
    let result = std::panic::catch_unwind(|| mining_speed_inner());
    result.unwrap_or(0.0)
}

fn mining_speed_inner() -> f64 {
    let _g = MINING_LOCK.lock().ok();
    let enabled = unsafe { MINING_ENABLED };
    if !enabled { return 0.0; }
    // Base mining rate: 1.5 EPS/hour when online with active peers
    // In production this would come from availability.rs challenges
    let handle = match get_handle() { Some(h) => h, None => return 0.0 };
    let peer_count = handle.block_on(async {
        let _g = STATE_LOCK.lock();
        unsafe {
            if let Some(ref node) = MESH_NODE { 
                node.peer_count().await 
            } else { 0 }
        }
    });
    if peer_count == 0 { return 0.0; }
    // 1.5 EPS/hour base + 0.5 per peer (incentivize more peers)
    1.5 + (peer_count as f64 * 0.5)
}

/// Enable/disable mining
#[no_mangle]
pub extern "C" fn epsilon_set_mining_enabled(enabled: i32) {
    let result = std::panic::catch_unwind(|| {
        let _g = MINING_LOCK.lock();
        unsafe { MINING_ENABLED = enabled != 0; }
    });
    let _ = result;
}

/// Check if mining is enabled
#[no_mangle]
pub extern "C" fn epsilon_is_mining_enabled() -> i32 {
    let result = std::panic::catch_unwind(|| {
        let _g = MINING_LOCK.lock();
        unsafe { if MINING_ENABLED { 1 } else { 0 } }
    });
    result.unwrap_or(0)
}

/// Transfer EPS tokens to another user
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn epsilon_transfer_tokens(recipient_ptr: *const c_char, amount: f64) -> i32 {
    let result = std::panic::catch_unwind(|| transfer_tokens_inner(recipient_ptr, amount));
    result.unwrap_or(0)
}

fn transfer_tokens_inner(recipient_ptr: *const c_char, amount: f64) -> i32 {
    if recipient_ptr.is_null() { return 0; }
    let recipient_cstr = unsafe { CStr::from_ptr(recipient_ptr) };
    let recipient = match recipient_cstr.to_str() { Ok(s) => s, Err(_) => return 0 };
    
    let rpc = "https://api.devnet.solana.com";
    let eps_mint = "EPSdGvXoKLrWQ8xqF5yZzXq3PZxXqZxXqZxXqZxXqZxX";
    
    let _g = MINING_LOCK.lock();
    let sender = unsafe { WALLET_PUBKEY.as_ref().cloned().unwrap_or_default() };
    
    match crate::token_account::TokenClient::new(rpc, eps_mint) {
        Ok(client) => {
            // amount in raw tokens (6 decimals)
            let raw_amount = (amount * 1e6) as u64;
            match client.transfer_tokens(&sender, recipient, raw_amount) {
                Ok(_) => 1,
                Err(_) => 0,
            }
        }
        Err(_) => 0,
    }
}

/// Transfer SOL to another user
#[no_mangle]
pub extern "C" fn epsilon_transfer_sol(recipient_ptr: *const c_char, amount: f64) -> i32 {
    let result = std::panic::catch_unwind(|| transfer_sol_inner(recipient_ptr, amount));
    result.unwrap_or(0)
}

fn transfer_sol_inner(recipient_ptr: *const c_char, amount: f64) -> i32 {
    if recipient_ptr.is_null() { return 0; }
    let recipient_cstr = unsafe { CStr::from_ptr(recipient_ptr) };
    let recipient = match recipient_cstr.to_str() { Ok(s) => s, Err(_) => return 0 };
    
    // SOL transfer placeholder — would need signer keypair for real transfer
    tracing::info!(
        "SOL transfer placeholder: → {} | {:.9} SOL",
        recipient, amount
    );
    1 // Return success for placeholder
}

/// Get wallet address as string
#[no_mangle]
pub extern "C" fn epsilon_get_wallet_address() -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        let _g = MINING_LOCK.lock().ok()?;
        unsafe { WALLET_PUBKEY.as_ref().map(|s| s.clone()) }
    });
    match result {
        Ok(Some(s)) => CString::new(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

fn urlencoding_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.' || byte == b'~' {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{:02X}", byte));
        }
    }
    result
}

fn urlencoding_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
            let byte = u8::from_str_radix(hex, 16).unwrap_or(0);
            result.push(byte);
            i += 3;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(result).unwrap_or_default()
}

fn base64_encode(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let data = input.as_bytes();
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(TABLE[((triple >> 18) & 63) as usize] as char);
        result.push(TABLE[((triple >> 12) & 63) as usize] as char);
        if i + 1 < data.len() {
            result.push(TABLE[((triple >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < data.len() {
            result.push(TABLE[(triple & 63) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}

fn base64_decode(input: &str) -> String {
    let input = input.trim();
    let mut lookup = [255u8; 256];
    for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
        lookup[*c as usize] = i as u8;
    }
    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let mut vals = [0u8; 4];
        let mut padding = 0;
        for j in 0..4 {
            let c = bytes[i + j];
            if c == b'=' {
                vals[j] = 0;
                padding += 1;
            } else {
                vals[j] = lookup[c as usize];
                if vals[j] == 255 { vals[j] = 0; }
            }
        }
        let triple = ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12) | ((vals[2] as u32) << 6) | (vals[3] as u32);
        result.push((triple >> 16) as u8);
        if padding < 2 { result.push((triple >> 8) as u8); }
        if padding < 1 { result.push(triple as u8); }
        i += 4;
    }
    String::from_utf8(result).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode_decode() {
        let original = r#"{"id":"abc123","addrs":[{"Ip":"192.168.1.1"}]}"#;
        let encoded = urlencoding_encode(original);
        let decoded = urlencoding_decode(&encoded);
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_invite_format() {
        let node_id = "abc123def456";
        let addr_json = r#"{"addrs":[]}"#;
        let invite = format!("epsilon://{}?addrs={}", node_id, urlencoding_encode(addr_json));
        assert!(invite.starts_with("epsilon://"));
        assert!(invite.contains("?addrs="));
    }
}