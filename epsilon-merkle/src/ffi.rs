//! FFI layer for Android JNI bridge.
//!
//! All functions are wrapped in `catch_unwind` to prevent Rust panics
//! from aborting the Android process (since we removed `panic = 'abort'`
//! from Cargo.toml, panics can now be caught).

use crate::gossip::{MeshMessage, MeshNode};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

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
    invite
}

#[no_mangle]
pub extern "C" fn epsilon_connect_peer(invite_ptr: *const c_char) -> i32 {
    let result = std::panic::catch_unwind(|| connect_peer_inner(invite_ptr));
    result.unwrap_or(0)
}

fn connect_peer_inner(invite_ptr: *const c_char) -> i32 {
    if invite_ptr.is_null() { return 0; }

    let invite_cstr = unsafe { CStr::from_ptr(invite_ptr) };
    let invite = match invite_cstr.to_str() { Ok(s) => s, Err(_) => return 0 };

    let addr_json = if let Some(rest) = invite.strip_prefix("epsilon://") {
        if let Some(qmark) = rest.find("?addrs=") {
            urlencoding_decode(&rest[qmark + 7..])
        } else { return 0; }
    } else {
        invite.to_string()
    };

    let handle = match get_handle() { Some(h) => h, None => return 0 };
    let ok = handle.block_on(async {
        let _g = STATE_LOCK.lock();
        unsafe {
            if let Some(ref node) = MESH_NODE {
                node.connect(&addr_json).await.is_ok()
            } else { false }
        }
    });
    if ok { 1 } else { 0 }
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
        let _g = STATE_LOCK.lock();
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