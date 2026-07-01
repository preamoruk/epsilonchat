//! Android JNI bridge — exports Rust functions to Java/Kotlin.
//!
//! On Android: functions are called via JNI from NativeBridge.java
//! On other platforms: stub implementations (for cargo build/test)

use std::os::raw::c_char;

/// Fake JNI types (on Android these come from jni-sys)
#[cfg(target_os = "android")]
type JNIEnv = *mut std::ffi::c_void;
#[cfg(target_os = "android")]
type jclass = *mut std::ffi::c_void;
#[cfg(target_os = "android")]
type jstring = *mut std::ffi::c_void;
#[cfg(target_os = "android")]
type jboolean = u8;
#[cfg(target_os = "android")]
type jobject = *mut std::ffi::c_void;

#[cfg(not(target_os = "android"))]
type JNIEnv = *mut std::ffi::c_void;
#[cfg(not(target_os = "android"))]
type jclass = *mut std::ffi::c_void;
#[cfg(not(target_os = "android"))]
type jstring = *mut std::ffi::c_void;
#[cfg(not(target_os = "android"))]
type jboolean = u8;
#[cfg(not(target_os = "android"))]
type jobject = *mut std::ffi::c_void;

/// JNI_TRUE
const JNI_TRUE: jboolean = 1;
/// JNI_FALSE
const JNI_FALSE: jboolean = 0;

/// Node ID string (set on init)
static mut NODE_ID: Option<String> = None;
static mut INITIALIZED: bool = false;

/// Initialize the mesh node
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn jni_start_mesh(_env: JNIEnv, _class: jclass) -> jstring {
    // On Android: would create MeshNode and return node ID
    // For now, return a stub
    let id = String::from("android-stub-node-id");
    unsafe {
        NODE_ID = Some(id.clone());
        INITIALIZED = true;
    }
    // In real impl: use env.NewStringUTF to create jstring from id
    std::ptr::null_mut()
}

#[cfg(not(target_os = "android"))]
#[no_mangle]
pub extern "system" fn jni_start_mesh(_env: JNIEnv, _class: jclass) -> jstring {
    let id = String::from("native-stub-node-id");
    unsafe {
        NODE_ID = Some(id);
        INITIALIZED = true;
    }
    std::ptr::null_mut()
}

/// Send a chat message
#[no_mangle]
pub extern "system" fn jni_send_message(
    _env: JNIEnv,
    _class: jclass,
    _text: jstring,
    _to: jstring,
) -> jboolean {
    // On Android: would extract strings from jstring and call ChatManager::send()
    // For now, return true (placeholder)
    JNI_TRUE
}

/// Get token balance (returns JSON string)
#[no_mangle]
pub extern "system" fn jni_get_balance(_env: JNIEnv, _class: jclass, _wallet: jstring) -> jstring {
    // On Android: would call TokenClient::get_token_balance and return JSON
    // For now, return null (placeholder)
    std::ptr::null_mut()
}

/// Generate an Iroh invite link
#[no_mangle]
pub extern "system" fn jni_generate_invite(_env: JNIEnv, _class: jclass) -> jstring {
    // On Android: would call MeshNode::invite_link()
    std::ptr::null_mut()
}

/// Connect to a peer via invite link
#[no_mangle]
pub extern "system" fn jni_connect(_env: JNIEnv, _class: jclass, _link: jstring) -> jboolean {
    // On Android: would call MeshNode::connect(link)
    JNI_TRUE
}

/// Get chat messages (returns JSON array string)
#[no_mangle]
pub extern "system" fn jni_get_messages(
    _env: JNIEnv,
    _class: jclass,
    _chat_id: jstring,
) -> jstring {
    // On Android: would call ChatManager::get_chat_history() and return JSON
    std::ptr::null_mut()
}

/// Request a Merkle proof (returns JSON string)
#[no_mangle]
pub extern "system" fn jni_request_proof(
    _env: JNIEnv,
    _class: jclass,
    _leaf_index: i64,
) -> jstring {
    std::ptr::null_mut()
}

/// Claim mining rewards
#[no_mangle]
pub extern "system" fn jni_claim_rewards(
    _env: JNIEnv,
    _class: jclass,
    _receipts_hash: jstring,
    _leaf_index: i64,
) -> jstring {
    std::ptr::null_mut()
}

// ===== Non-JNI helper functions (for testing on non-Android) =====

/// Get whether the native bridge is initialized
pub fn is_initialized() -> bool {
    unsafe { INITIALIZED }
}

/// Get the node ID (for testing)
pub fn get_node_id() -> Option<String> {
    unsafe { NODE_ID.clone() }
}

/// Reset state (for testing)
pub fn reset() {
    unsafe {
        NODE_ID = None;
        INITIALIZED = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        reset();
        assert!(!is_initialized());
        assert!(get_node_id().is_none());

        jni_start_mesh(std::ptr::null_mut(), std::ptr::null_mut());

        assert!(is_initialized());
        assert!(get_node_id().is_some());
    }

    #[test]
    fn test_send_message_stub() {
        let result = jni_send_message(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(result, JNI_TRUE);
    }

    #[test]
    fn test_connect_stub() {
        let result = jni_connect(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(result, JNI_TRUE);
    }

    #[test]
    fn test_constants() {
        assert_eq!(JNI_TRUE, 1);
        assert_eq!(JNI_FALSE, 0);
    }

    #[test]
    fn test_reset() {
        jni_start_mesh(std::ptr::null_mut(), std::ptr::null_mut());
        assert!(is_initialized());
        reset();
        assert!(!is_initialized());
        assert!(get_node_id().is_none());
    }
}
