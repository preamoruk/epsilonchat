//! Chat messaging layer — a lightweight Delta Chat core replacement built on
//! top of the Iroh mesh transport (`crate::gossip`).
//!
//! This module provides the essential chat primitives used by EpsilonChat
//! peers:
//!
//! - [`ChatMessageData`] — a signed, optionally-replied-to, soft-deletable
//!   chat message (richer than the ephemeral [`crate::gossip::MeshMessage::ChatMessage`]).
//! - [`ChatStore`] — local message storage with in-memory indexing and
//!   JSON-on-disk persistence, including read/unread tracking and signature
//!   verification.
//! - [`Contact`] / [`ContactStore`] — a peer address book keyed by Iroh node ID,
//!   each entry carrying an ed25519 public key for message verification.
//! - [`GroupChat`] / [`GroupStore`] — multi-party group chats addressed as
//!   `group:<id>` in the message `to` field.
//! - [`ChatManager`] — ties the three stores together with a per-node signing
//!   key, providing `send`, `receive`, and history-retrieval operations.
//!
//! All message integrity is provided by ed25519 signatures (via
//! `ed25519_dalek`) over a SHA-256 message hash, so that peers can
//! independently verify that a message genuinely originated from the claimed
//! sender without trusting the mesh transport.

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hash of the canonical message content.
///
/// The digest covers `from`, `to`, `text`, and `timestamp` (little-endian),
/// in that fixed order. Changing any of those fields changes the hash and
/// therefore invalidates the signature.
pub fn message_hash(from: &str, to: &str, text: &str, timestamp: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(from.as_bytes());
    hasher.update(to.as_bytes());
    hasher.update(text.as_bytes());
    hasher.update(timestamp.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Render a 32-byte hash as a lowercase hex string.
fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// Current unix timestamp in seconds (best-effort, never panics).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// ChatMessageData
// ---------------------------------------------------------------------------

/// A chat message with cryptographic signature, soft-delete, and reply support.
///
/// This is the durable counterpart to the ephemeral
/// [`crate::gossip::MeshMessage::ChatMessage`]: it is what gets stored locally
/// and verified on receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessageData {
    /// Message identifier (hex SHA-256 of `from || to || text || timestamp`).
    pub id: String,
    /// Sender node ID (Iroh endpoint ID).
    pub from: String,
    /// Recipient node ID, or `group:<group_id>` for group messages.
    pub to: String,
    /// Message body (supports markdown).
    pub text: String,
    /// Unix timestamp (seconds) when the message was created.
    pub timestamp: u64,
    /// Ed25519 signature over the message hash.
    pub signature: Vec<u8>,
    /// ID of the message being replied to, if any.
    pub reply_to: Option<String>,
    /// Soft-delete flag. Deleted messages remain on disk but `text` is
    /// considered withdrawn.
    pub deleted: bool,
}

impl ChatMessageData {
    /// Compute the message hash from its content fields.
    pub fn hash(&self) -> [u8; 32] {
        message_hash(&self.from, &self.to, &self.text, self.timestamp)
    }

    /// Construct an unsigned message (signature empty). The caller is expected
    /// to sign `hash()` afterwards.
    fn build(from: String, to: String, text: String, timestamp: u64, reply_to: Option<String>) -> Self {
        let hash = message_hash(&from, &to, &text, timestamp);
        Self {
            id: hex32(&hash),
            from,
            to,
            text,
            timestamp,
            signature: Vec::new(),
            reply_to,
            deleted: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ChatStore
// ---------------------------------------------------------------------------

/// Local message storage.
///
/// Messages are kept in memory in a single `Vec` and optionally persisted to
/// a JSON file under `data_dir/messages.json`. Read/unread state is tracked
/// per chat partner (or group) ID.
#[derive(Clone, Debug)]
pub struct ChatStore {
    /// All known messages (sent and received), in insertion order.
    pub messages: Vec<ChatMessageData>,
    /// On-disk persistence directory.
    pub data_dir: String,
    /// Set of chat IDs that have been fully read. A chat ID is either a peer
    /// node ID or `group:<group_id>`. Messages whose `to` or `from` matches a
    /// chat ID and that are not in this set are considered unread.
    read_chats: HashSet<String>,
}

impl ChatStore {
    /// Create an empty store rooted at `data_dir`.
    pub fn new(data_dir: impl Into<String>) -> Self {
        Self {
            messages: Vec::new(),
            data_dir: data_dir.into(),
            read_chats: HashSet::new(),
        }
    }

    /// Create, sign, store, and return a message.
    ///
    /// `from` is the local node ID; `to` is a peer node ID or `group:<id>`.
    /// `signing_key` is the sender's ed25519 secret key.
    pub fn send_message(
        &mut self,
        from: &str,
        to: &str,
        text: &str,
        reply_to: Option<String>,
        signing_key: &SigningKey,
    ) -> ChatMessageData {
        let timestamp = now_unix();
        let mut msg = ChatMessageData::build(from.to_string(), to.to_string(), text.to_string(), timestamp, reply_to);
        let hash = msg.hash();
        let sig = signing_key.sign(&hash);
        msg.signature = sig.to_bytes().to_vec();
        self.messages.push(msg.clone());
        msg
    }

    /// Store a received message. Returns `true` if the message is new (not a
    /// duplicate by ID).
    pub fn receive_message(&mut self, msg: ChatMessageData) -> bool {
        if self.messages.iter().any(|m| m.id == msg.id) {
            return false;
        }
        self.messages.push(msg);
        true
    }

    /// Resolve the chat ID for a given message: the counterpart of `self.node_id`
    /// in a 1:1 chat, or the `to` field (e.g. `group:xxx`) for group chats.
    fn chat_id_of(msg: &ChatMessageData, self_node: &str) -> String {
        if msg.to.starts_with("group:") {
            msg.to.clone()
        } else if msg.from == self_node {
            msg.to.clone()
        } else {
            msg.from.clone()
        }
    }

    /// Return messages belonging to a chat (peer node ID or `group:<id>`),
    /// sorted by ascending timestamp, limited to `limit` (most recent) entries.
    pub fn get_messages(&self, chat_id: &str, limit: usize) -> Vec<ChatMessageData> {
        let mut filtered: Vec<ChatMessageData> = self
            .messages
            .iter()
            .filter(|m| {
                if chat_id.starts_with("group:") {
                    m.to == chat_id
                } else {
                    // 1:1 chat: either direction between self and partner.
                    (m.from == chat_id || m.to == chat_id)
                }
            })
            .cloned()
            .collect();
        filtered.sort_by_key(|m| m.timestamp);
        if limit == 0 {
            return filtered;
        }
        let len = filtered.len();
        if len > limit {
            filtered[len - limit..].to_vec()
        } else {
            filtered
        }
    }

    /// Number of unread messages in a chat.
    ///
    /// A chat is unread if its chat ID is not in `read_chats`. This counts
    /// non-deleted messages belonging to the chat (either direction for a
    /// 1:1 chat, or `group:<id>` for group chats).
    pub fn get_unread_count(&self, chat_id: &str) -> usize {
        if self.read_chats.contains(chat_id) {
            return 0;
        }
        self.messages
            .iter()
            .filter(|m| {
                if m.deleted {
                    return false;
                }
                if chat_id.starts_with("group:") {
                    m.to == chat_id
                } else {
                    m.from == chat_id || m.to == chat_id
                }
            })
            .count()
    }

    /// Mark all messages in a chat as read.
    pub fn mark_read(&mut self, chat_id: &str) {
        self.read_chats.insert(chat_id.to_string());
    }

    /// Soft-delete a message by ID. Returns `true` if a message was found and
    /// flagged.
    pub fn delete_message(&mut self, id: &str) -> bool {
        if let Some(m) = self.messages.iter_mut().find(|m| m.id == id) {
            m.deleted = true;
            true
        } else {
            false
        }
    }

    /// Persist messages to `<data_dir>/messages.json` (JSON array).
    pub fn save_to_disk(&self) -> Result<()> {
        let dir = PathBuf::from(&self.data_dir);
        std::fs::create_dir_all(&dir).ok();
        let json = serde_json::to_vec_pretty(&self.messages)
            .context("failed to serialize messages")?;
        let path = dir.join("messages.json");
        std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Load messages from `<data_dir>/messages.json`, replacing in-memory state.
    pub fn load_from_disk(&mut self) -> Result<()> {
        let path = PathBuf::from(&self.data_dir).join("messages.json");
        let data = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let msgs: Vec<ChatMessageData> = serde_json::from_slice(&data)
            .context("failed to deserialize messages")?;
        self.messages = msgs;
        Ok(())
    }

    /// Verify a message's ed25519 signature against the sender's public key.
    pub fn verify_message(msg: &ChatMessageData, sender_pubkey: &[u8; 32]) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(sender_pubkey) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let signature = match Signature::from_slice(&msg.signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        let hash = msg.hash();
        verifying_key.verify(&hash, &signature).is_ok()
    }
}

/// Helper used by `get_unread_count`: decide whether a message belongs to the
/// given chat ID for unread-counting purposes.
fn chat_id_or_partner(msg: &ChatMessageData, chat_id: &str) -> String {
    if msg.to.starts_with("group:") {
        msg.to.clone()
    } else if msg.from == chat_id {
        // received from chat_id
        msg.from.clone()
    } else if msg.to == chat_id {
        // sent to chat_id — still counts toward the chat, but not as unread
        msg.to.clone()
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Contact
// ---------------------------------------------------------------------------

/// A peer contact: Iroh node ID, display name, and ed25519 public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    /// Iroh endpoint ID (used as the addressing key).
    pub node_id: String,
    /// Human-readable display name.
    pub name: String,
    /// Ed25519 public key for signature verification.
    pub pubkey: [u8; 32],
    /// Optional Iroh invite link for (re)connecting.
    pub invite_link: Option<String>,
    /// Unix timestamp (seconds) of last presence.
    pub last_seen: u64,
    /// Whether the peer is currently online (recent heartbeat seen).
    pub online: bool,
}

// ---------------------------------------------------------------------------
// ContactStore
// ---------------------------------------------------------------------------

/// In-memory address book of known peers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ContactStore {
    /// All known contacts.
    pub contacts: Vec<Contact>,
}

impl ContactStore {
    /// Add a new contact. If a contact with the same `node_id` already exists,
    /// it is replaced.
    pub fn add_contact(&mut self, node_id: &str, name: &str, pubkey: [u8; 32]) -> Contact {
        let contact = Contact {
            node_id: node_id.to_string(),
            name: name.to_string(),
            pubkey,
            invite_link: None,
            last_seen: now_unix(),
            online: false,
        };
        if let Some(existing) = self.contacts.iter_mut().find(|c| c.node_id == node_id) {
            *existing = contact.clone();
        } else {
            self.contacts.push(contact.clone());
        }
        contact
    }

    /// Remove a contact by node ID. Returns `true` if a contact was removed.
    pub fn remove_contact(&mut self, node_id: &str) -> bool {
        let before = self.contacts.len();
        self.contacts.retain(|c| c.node_id != node_id);
        self.contacts.len() < before
    }

    /// Look up a contact by node ID.
    pub fn get_contact(&self, node_id: &str) -> Option<Contact> {
        self.contacts.iter().find(|c| c.node_id == node_id).cloned()
    }

    /// Update a contact's online status and `last_seen` timestamp.
    pub fn update_online_status(&mut self, node_id: &str, online: bool) {
        if let Some(c) = self.contacts.iter_mut().find(|c| c.node_id == node_id) {
            c.online = online;
            c.last_seen = now_unix();
        }
    }

    /// Return all known contacts.
    pub fn list_contacts(&self) -> Vec<Contact> {
        self.contacts.clone()
    }
}

// ---------------------------------------------------------------------------
// GroupChat
// ---------------------------------------------------------------------------

/// A multi-party group chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupChat {
    /// Group ID (hex SHA-256 of `creator || members.join(',') || created_at`).
    pub id: String,
    /// Human-readable group name.
    pub name: String,
    /// Member node IDs.
    pub members: Vec<String>,
    /// Creator node ID.
    pub created_by: String,
    /// Unix timestamp (seconds) of creation.
    pub created_at: u64,
}

/// Compute a deterministic group ID.
fn group_id(creator: &str, members: &[String], created_at: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(creator.as_bytes());
    for m in members {
        hasher.update(m.as_bytes());
    }
    hasher.update(created_at.to_le_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

// ---------------------------------------------------------------------------
// GroupStore
// ---------------------------------------------------------------------------

/// In-memory store of group chats.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GroupStore {
    /// All known groups.
    pub groups: Vec<GroupChat>,
}

impl GroupStore {
    /// Create a new group and store it. The creator is automatically included
    /// in the member list if not already present.
    pub fn create_group(&mut self, name: &str, members: Vec<String>, creator: &str) -> GroupChat {
        let mut all_members = members;
        if !all_members.iter().any(|m| m == creator) {
            all_members.push(creator.to_string());
        }
        let created_at = now_unix();
        let id = group_id(creator, &all_members, created_at);
        let group = GroupChat {
            id,
            name: name.to_string(),
            members: all_members,
            created_by: creator.to_string(),
            created_at,
        };
        self.groups.push(group.clone());
        group
    }

    /// Add a member to a group. Returns `true` if the member was added (i.e.
    /// was not already a member).
    pub fn add_member(&mut self, group_id: &str, node_id: &str) -> bool {
        if let Some(g) = self.groups.iter_mut().find(|g| g.id == group_id) {
            if g.members.iter().any(|m| m == node_id) {
                return false;
            }
            g.members.push(node_id.to_string());
            return true;
        }
        false
    }

    /// Remove a member from a group. Returns `true` if the member was removed.
    /// The creator cannot be removed.
    pub fn remove_member(&mut self, group_id: &str, node_id: &str) -> bool {
        if let Some(g) = self.groups.iter_mut().find(|g| g.id == group_id) {
            if g.created_by == node_id {
                return false;
            }
            let before = g.members.len();
            g.members.retain(|m| m != node_id);
            return g.members.len() < before;
        }
        false
    }

    /// Look up a group by ID.
    pub fn get_group(&self, group_id: &str) -> Option<GroupChat> {
        self.groups.iter().find(|g| g.id == group_id).cloned()
    }

    /// Return all groups.
    pub fn list_groups(&self) -> Vec<GroupChat> {
        self.groups.clone()
    }
}

// ---------------------------------------------------------------------------
// ChatManager
// ---------------------------------------------------------------------------

/// High-level chat facade tying together messages, contacts, and groups with
/// a per-node signing key.
#[derive(Clone, Debug)]
pub struct ChatManager {
    /// Message store.
    pub messages: ChatStore,
    /// Contact store.
    pub contacts: ContactStore,
    /// Group store.
    pub groups: GroupStore,
    /// Local node's ed25519 signing key.
    pub signing_key: SigningKey,
    /// Local node's Iroh endpoint ID.
    pub node_id: String,
}

impl ChatManager {
    /// Create a new chat manager.
    pub fn new(data_dir: impl Into<String>, node_id: String, signing_key: SigningKey) -> Self {
        Self {
            messages: ChatStore::new(data_dir),
            contacts: ContactStore::default(),
            groups: GroupStore::default(),
            signing_key,
            node_id,
        }
    }

    /// Send a 1:1 message to `to` (a peer node ID).
    pub fn send(&mut self, to: &str, text: &str) -> Result<ChatMessageData> {
        if to.is_empty() {
            anyhow::bail!("recipient is empty");
        }
        if text.is_empty() {
            anyhow::bail!("message text is empty");
        }
        Ok(self.messages.send_message(&self.node_id, to, text, None, &self.signing_key))
    }

    /// Send a message to a group. The `to` field is set to `group:<group_id>`.
    pub fn send_group(&mut self, group_id: &str, text: &str) -> Result<ChatMessageData> {
        if group_id.is_empty() {
            anyhow::bail!("group_id is empty");
        }
        if text.is_empty() {
            anyhow::bail!("message text is empty");
        }
        if self.groups.get_group(group_id).is_none() {
            anyhow::bail!("unknown group: {}", group_id);
        }
        let to = format!("group:{}", group_id);
        Ok(self.messages.send_message(&self.node_id, &to, text, None, &self.signing_key))
    }

    /// Receive a message from the mesh. Returns `true` if it was new.
    pub fn receive(&mut self, msg: ChatMessageData) -> bool {
        self.messages.receive_message(msg)
    }

    /// Retrieve 1:1 chat history with `partner`.
    pub fn get_chat_history(&self, partner: &str, limit: usize) -> Vec<ChatMessageData> {
        self.messages.get_messages(partner, limit)
    }

    /// Retrieve group chat history.
    pub fn get_group_history(&self, group_id: &str, limit: usize) -> Vec<ChatMessageData> {
        let chat_id = format!("group:{}", group_id);
        self.messages.get_messages(&chat_id, limit)
    }

    /// Local node's public key (for sharing with contacts).
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a signing key from a fixed seed (deterministic for tests).
    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn make_manager(seed: u8) -> ChatManager {
        ChatManager::new("./.epsilon/test-chat", format!("node-{}", seed), test_key(seed))
    }

    // 1. send + receive round-trip ------------------------------------------------
    #[test]
    fn test_send_and_receive() {
        let mut alice = make_manager(1);
        let msg = alice.send("bob", "hello bob").unwrap();
        assert_eq!(msg.from, "node-1");
        assert_eq!(msg.to, "bob");
        assert_eq!(msg.text, "hello bob");
        assert!(!msg.signature.is_empty());

        let mut bob = make_manager(2);
        let is_new = bob.receive(msg);
        assert!(is_new, "first receive should be new");
    }

    // 2. duplicate receive returns false -----------------------------------------
    #[test]
    fn test_receive_duplicate() {
        let mut bob = make_manager(2);
        let msg = ChatMessageData {
            id: "deadbeef".into(),
            from: "alice".into(),
            to: "bob".into(),
            text: "hi".into(),
            timestamp: 1,
            signature: vec![],
            reply_to: None,
            deleted: false,
        };
        assert!(bob.receive(msg.clone()));
        assert!(!bob.receive(msg), "second receive should not be new");
    }

    // 3. signature verification ---------------------------------------------------
    #[test]
    fn test_verify_message_signature() {
        let mut alice = make_manager(1);
        let msg = alice.send("bob", "signed message").unwrap();
        let pubkey = alice.public_key();
        assert!(ChatStore::verify_message(&msg, &pubkey), "signature must verify");
    }

    // 4. verification fails with wrong key ---------------------------------------
    #[test]
    fn test_verify_wrong_key_fails() {
        let mut alice = make_manager(1);
        let msg = alice.send("bob", "signed message").unwrap();
        let wrong_pubkey = test_key(99).verifying_key().to_bytes();
        assert!(!ChatStore::verify_message(&msg, &wrong_pubkey));
    }

    // 5. verification fails on tampered text --------------------------------------
    #[test]
    fn test_verify_tampered_text_fails() {
        let mut alice = make_manager(1);
        let mut msg = alice.send("bob", "original").unwrap();
        let pubkey = alice.public_key();
        msg.text = "tampered".into();
        assert!(!ChatStore::verify_message(&msg, &pubkey));
    }

    // 6. message history retrieval ------------------------------------------------
    #[test]
    fn test_message_history() {
        let mut alice = make_manager(1);
        // Send a few messages to bob with controlled timestamps via direct build.
        for i in 0..5u64 {
            let mut m = ChatMessageData::build(
                "node-1".into(),
                "bob".into(),
                format!("msg {}", i),
                1000 + i,
                None,
            );
            m.signature = alice.signing_key.sign(&m.hash()).to_bytes().to_vec();
            alice.messages.receive_message(m);
        }
        let hist = alice.get_chat_history("bob", 10);
        assert_eq!(hist.len(), 5, "should retrieve all 5 messages");
        // Sorted ascending by timestamp.
        assert_eq!(hist[0].text, "msg 0");
        assert_eq!(hist[4].text, "msg 4");

        // Limit to last 2.
        let recent = alice.get_chat_history("bob", 2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].text, "msg 3");
        assert_eq!(recent[1].text, "msg 4");
    }

    // 7. unread count + mark_read -------------------------------------------------
    #[test]
    fn test_unread_count_and_mark_read() {
        let mut bob = make_manager(2);
        // Two messages from alice to bob.
        for i in 0..3u64 {
            let m = ChatMessageData {
                id: format!("id{}", i),
                from: "alice".into(),
                to: "bob".into(),
                text: format!("m{}", i),
                timestamp: i,
                signature: vec![],
                reply_to: None,
                deleted: false,
            };
            bob.receive(m);
        }
        // Before mark_read: unread count reflects un-read chat.
        // (Our model: any chat not in read_chats has unread messages.)
        let unread = bob.messages.get_unread_count("alice");
        assert!(unread > 0, "should have unread messages");

        bob.messages.mark_read("alice");
        assert_eq!(bob.messages.get_unread_count("alice"), 0, "should be read after mark_read");
    }

    // 8. soft delete --------------------------------------------------------------
    #[test]
    fn test_soft_delete() {
        let mut alice = make_manager(1);
        let msg = alice.send("bob", "to be deleted").unwrap();
        assert!(!msg.deleted);

        let deleted = alice.messages.delete_message(&msg.id);
        assert!(deleted, "delete should find the message");

        let stored = alice.messages.messages.iter().find(|m| m.id == msg.id).unwrap();
        assert!(stored.deleted, "message should be flagged deleted");
    }

    // 9. persistence: save + load -------------------------------------------------
    #[test]
    fn test_persistence_save_load() {
        let tmp = format!("./.epsilon/test-chat-persist-{}", now_unix());
        let mut alice = ChatManager::new(tmp.clone(), "alice".into(), test_key(7));
        let m1 = alice.send("bob", "persist me").unwrap();
        let m2 = alice.send("bob", "and me too").unwrap();

        alice.messages.save_to_disk().expect("save should succeed");

        let mut reloaded = ChatStore::new(tmp.clone());
        reloaded.load_from_disk().expect("load should succeed");
        assert_eq!(reloaded.messages.len(), 2, "should load 2 messages");
        assert!(reloaded.messages.iter().any(|m| m.id == m1.id));
        assert!(reloaded.messages.iter().any(|m| m.id == m2.id));

        // Cleanup.
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // 10. contacts CRUD -----------------------------------------------------------
    #[test]
    fn test_contacts_crud() {
        let mut store = ContactStore::default();
        let pk = [42u8; 32];
        let c = store.add_contact("node-x", "Alice", pk);
        assert_eq!(c.node_id, "node-x");
        assert_eq!(c.name, "Alice");
        assert_eq!(c.pubkey, pk);

        assert_eq!(store.list_contacts().len(), 1);
        assert!(store.get_contact("node-x").is_some());
        assert!(store.get_contact("missing").is_none());

        // Replace existing.
        let c2 = store.add_contact("node-x", "Alice 2", pk);
        assert_eq!(c2.name, "Alice 2");
        assert_eq!(store.list_contacts().len(), 1, "replace should not duplicate");

        store.update_online_status("node-x", true);
        assert!(store.get_contact("node-x").unwrap().online);

        assert!(store.remove_contact("node-x"));
        assert!(store.get_contact("node-x").is_none());
        assert!(!store.remove_contact("node-x"), "removing again should return false");
    }

    // 11. group creation + membership --------------------------------------------
    #[test]
    fn test_group_create_and_members() {
        let mut store = GroupStore::default();
        let g = store.create_group("devs", vec!["bob".into(), "carol".into()], "alice");
        assert_eq!(g.name, "devs");
        assert_eq!(g.created_by, "alice");
        // Creator auto-added.
        assert!(g.members.contains(&"alice".into()));
        assert!(g.members.contains(&"bob".into()));
        assert!(g.members.contains(&"carol".into()));
        assert_eq!(g.members.len(), 3);

        assert_eq!(store.list_groups().len(), 1);

        // Add member.
        assert!(store.add_member(&g.id, "dave"));
        assert!(!store.add_member(&g.id, "dave"), "duplicate add returns false");
        let g2 = store.get_group(&g.id).unwrap();
        assert!(g2.members.contains(&"dave".into()));

        // Remove member (non-creator).
        assert!(store.remove_member(&g.id, "dave"));
        let g3 = store.get_group(&g.id).unwrap();
        assert!(!g3.members.contains(&"dave".into()));

        // Creator cannot be removed.
        assert!(!store.remove_member(&g.id, "alice"));
        let g4 = store.get_group(&g.id).unwrap();
        assert!(g4.members.contains(&"alice".into()));
    }

    // 12. group send + history ----------------------------------------------------
    #[test]
    fn test_group_send_and_history() {
        let mut alice = make_manager(1);
        let g = alice.groups.create_group("team", vec!["bob".into()], "node-1");

        let m = alice.send_group(&g.id, "hi team").unwrap();
        assert_eq!(m.to, format!("group:{}", g.id));
        assert_eq!(m.text, "hi team");

        let hist = alice.get_group_history(&g.id, 10);
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].text, "hi team");
    }

    // 13. send_group to unknown group fails ----------------------------------------
    #[test]
    fn test_send_group_unknown_fails() {
        let mut alice = make_manager(1);
        let res = alice.send_group("nonexistent", "hi");
        assert!(res.is_err());
    }

    // 14. message_hash is deterministic and content-sensitive ---------------------
    #[test]
    fn test_message_hash_properties() {
        let h1 = message_hash("alice", "bob", "hello", 1000);
        let h2 = message_hash("alice", "bob", "hello", 1000);
        assert_eq!(h1, h2, "same inputs => same hash");

        let h3 = message_hash("alice", "bob", "hello", 1001);
        assert_ne!(h1, h3, "different timestamp => different hash");

        let h4 = message_hash("alice", "bob", "Hello", 1000);
        assert_ne!(h1, h4, "different text => different hash");

        let h5 = message_hash("alice", "carol", "hello", 1000);
        assert_ne!(h1, h5, "different recipient => different hash");
    }

    // 15. reply_to field is carried through ---------------------------------------
    #[test]
    fn test_reply_to_field() {
        let mut alice = make_manager(1);
        let original = alice.send("bob", "original").unwrap();

        // Build a reply manually with reply_to set, sign it, and receive it.
        let timestamp = now_unix();
        let mut reply = ChatMessageData::build(
            alice.node_id.clone(),
            "bob".into(),
            "reply".into(),
            timestamp,
            Some(original.id.clone()),
        );
        let sig = alice.signing_key.sign(&reply.hash());
        reply.signature = sig.to_bytes().to_vec();
        let reply_id = reply.id.clone();

        assert!(alice.receive(reply), "reply should be stored as new");
        let hist = alice.get_chat_history("bob", 10);
        let r = hist.iter().find(|m| m.id == reply_id).unwrap();
        assert_eq!(r.reply_to, Some(original.id));
    }
}