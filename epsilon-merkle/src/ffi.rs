//! FFI layer for Android JNI bridge.
//!
//! Provides simple C-callable functions that the Java side calls via JNI:
//! - epsilon_start_mesh() — start Iroh endpoint, return node ID
//! - epsilon_get_invite() — get invite string (node ID + addresses)
//! - epsilon_connect_peer(invite) — connect to another peer
//! - epsilon_send_message(text) — broadcast a chat message to all peers
//! - epsilon_recv_message() — poll for received messages (non-blocking)
//! - epsilon_peer_count() — get number of connected peers

use crate::gossip::{MeshMessage, MeshNode};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

/// Global mesh node state
static mut MESH_NODE: Option<Arc<MeshNode>> = None;

/// Global runtime for async operations
static mut RUNTIME: Option<tokio::runtime::Runtime> = None;

/// Received message queue (polled from Java)
static mut RECV_QUEUE: Vec<String> = Vec::new();

/// Lock for accessing global state
static STATE_LOCK: Mutex<()> = Mutex::new(());

fn get_handle() -> Option<tokio::runtime::Handle> {
    let _guard = STATE_LOCK.lock().ok()?;
    unsafe {
        RUNTIME.as_ref().map(|r| r.handle().clone())
    }
}

/// Start the mesh node. Returns node ID string (caller must free with epsilon_free_string).
#[no_mangle]
pub extern "C" fn epsilon_start_mesh() -> *mut c_char {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };
    let handle = rt.handle().clone();

    let node_id = handle.block_on(async move {
        let _guard = STATE_LOCK.lock().ok();

        // Save runtime
        unsafe {
            if RUNTIME.is_none() {
                RUNTIME = Some(rt);
            }
        }

        // Create mesh node as phone
        let node = match MeshNode::new(false).await {
            Ok(n) => Arc::new(n),
            Err(_) => return None,
        };

        // Start accept loop
        let accept_node = node.clone();
        accept_node.start_accept_loop();

        // Start message receiver
        let rx_node = node.clone();
        let mut rx = rx_node.subscribe();
        tokio::spawn(async move {
            while let Ok(msg) = rx.recv().await {
                if let MeshMessage::ChatMessage { from, text, .. } = msg {
                    let formatted = format!("{}: {}", from, text);
                    let _g = STATE_LOCK.lock();
                    unsafe {
                        RECV_QUEUE.push(formatted);
                    }
                }
            }
        });

        // Save node
        unsafe {
            MESH_NODE = Some(node.clone());
        }

        Some(node.id().to_string())
    });

    match node_id {
        Some(id) => CString::new(id).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Get the invite string for this node.
#[no_mangle]
pub extern "C" fn epsilon_get_invite() -> *mut c_char {
    let handle = match get_handle() {
        Some(h) => h,
        None => return std::ptr::null_mut(),
    };

    let invite = handle.block_on(async {
        let _g = STATE_LOCK.lock();
        unsafe {
            if let Some(ref node) = MESH_NODE {
                let node_id = node.id().to_string();
                let addr = node.addr();
                let addr_json = serde_json::to_string(&addr).unwrap_or_default();
                Some(format!("epsilon://{}?addrs={}", node_id, urlencoding_encode(&addr_json)))
            } else {
                None
            }
        }
    });

    match invite {
        Some(s) => CString::new(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Connect to a peer using their invite string. Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn epsilon_connect_peer(invite_ptr: *const c_char) -> i32 {
    if invite_ptr.is_null() {
        return 0;
    }

    let invite_cstr = unsafe { CStr::from_ptr(invite_ptr) };
    let invite = match invite_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let addr_json = if let Some(rest) = invite.strip_prefix("epsilon://") {
        if let Some(qmark) = rest.find("?addrs=") {
            let encoded = &rest[qmark + 7..];
            urlencoding_decode(encoded)
        } else {
            return 0;
        }
    } else {
        invite.to_string()
    };

    let handle = match get_handle() {
        Some(h) => h,
        None => return 0,
    };

    let ok = handle.block_on(async {
        let _g = STATE_LOCK.lock();
        unsafe {
            if let Some(ref node) = MESH_NODE {
                node.connect(&addr_json).await.is_ok()
            } else {
                false
            }
        }
    });

    if ok { 1 } else { 0 }
}

/// Send a chat message to all connected peers. Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn epsilon_send_message(text_ptr: *const c_char) -> i32 {
    if text_ptr.is_null() {
        return 0;
    }

    let text_cstr = unsafe { CStr::from_ptr(text_ptr) };
    let text = match text_cstr.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return 0,
    };

    let handle = match get_handle() {
        Some(h) => h,
        None => return 0,
    };

    let ok = handle.block_on(async {
        let _g = STATE_LOCK.lock();
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
            } else {
                false
            }
        }
    });

    if ok { 1 } else { 0 }
}

/// Poll for a received message (non-blocking). Returns NULL if no message available.
#[no_mangle]
pub extern "C" fn epsilon_recv_message() -> *mut c_char {
    let handle = match get_handle() {
        Some(h) => h,
        None => return std::ptr::null_mut(),
    };

    let msg = handle.block_on(async {
        let _g = STATE_LOCK.lock();
        unsafe { RECV_QUEUE.pop() }
    });

    match msg {
        Some(s) => CString::new(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Get the number of connected peers.
#[no_mangle]
pub extern "C" fn epsilon_peer_count() -> i32 {
    let handle = match get_handle() {
        Some(h) => h,
        None => return 0,
    };

    let count = handle.block_on(async {
        let _g = STATE_LOCK.lock();
        unsafe {
            if let Some(ref node) = MESH_NODE {
                node.peer_count().await
            } else {
                0
            }
        }
    });

    count as i32
}

/// Free a C string returned by epsilon functions.
#[no_mangle]
pub extern "C" fn epsilon_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

/// Simple URL-encoding
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

/// Simple URL-decoding
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