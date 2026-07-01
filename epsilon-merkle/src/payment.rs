//! Token as P2P Payment — bridges the chat messaging layer (`crate::chat_core`)
//! with the SPL token layer (`crate::token_account`).
//!
//! This module lets peers attach token payment requests to chat messages,
//! confirm them with on-chain transaction signatures, and reconcile the
//! resulting receipts via a local [`PaymentLedger`]. Batch hashes produced by
//! [`PaymentManager::batch_payments`] are suitable as leaves for the mesh
//! Merkle tree settlement layer.
//!
//! # Design
//!
//! - [`PaymentMessage`] is the *request* side: created when a sender attaches
//!   a payment to a chat message and stored alongside the chat bubble until the
//!   on-chain transfer is confirmed.
//! - [`PaymentReceipt`] is the *settled* side: produced once the transaction
//!   signature is verified (or rejected) and persisted in the
//!   [`PaymentLedger`].
//! - [`PaymentManager`] is stateless aside from the configured token mint, so
//!   it can be freely cloned across tasks.
//! - [`PaymentLedger`] is the persistent on-disk-ish (in-memory here) record of
//!   all settled receipts, indexed by chat message id.
//!
//! All hashing uses SHA-256 via `sha2`, consistent with the rest of the crate.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;

use crate::token_account::{EPSILON_TOKEN_DECIMALS, EPSILON_TOKEN_SYMBOL};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Best-effort unix timestamp in seconds (never panics).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Render a raw token amount (6-decimal EPS) as a UI string like `5.00`.
fn format_ui_amount(raw: u64) -> String {
    let ui = raw as f64 / 10f64.powi(EPSILON_TOKEN_DECIMALS as i32);
    // Two decimals is enough for a chat bubble; this matches the `5.00` style
    // used in the spec.
    format!("{:.2}", ui)
}

// ---------------------------------------------------------------------------
// PaymentStatus
// ---------------------------------------------------------------------------

/// Lifecycle status of a payment attached to a chat message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// Payment request created but not yet confirmed on-chain.
    Pending,
    /// On-chain transaction verified — tokens are considered delivered.
    Confirmed,
    /// Payment was rejected by the recipient, failed on-chain, or expired.
    Failed,
}

// ---------------------------------------------------------------------------
// PaymentMessage
// ---------------------------------------------------------------------------

/// A payment request attached to a chat message.
///
/// Created by [`PaymentManager::attach_payment`] and later confirmed (with an
/// on-chain transaction signature) or rejected.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentMessage {
    /// Sender wallet pubkey.
    pub sender: Pubkey,
    /// Recipient wallet pubkey.
    pub recipient: Pubkey,
    /// Raw token amount (6-decimal EPS).
    pub amount: u64,
    /// Token mint this payment is denominated in.
    pub token_mint: Pubkey,
    /// ID of the chat message this payment is attached to.
    pub chat_message_id: u64,
    /// Human-readable memo included with the payment (e.g. "for coffee").
    pub memo: String,
    /// On-chain transaction signature once confirmed (empty while pending).
    pub tx_signature: Vec<u8>,
    /// Unix timestamp (seconds) of creation.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// PaymentReceipt
// ---------------------------------------------------------------------------

/// A settled payment record persisted in the [`PaymentLedger`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Chat message id this receipt corresponds to.
    pub message_id: u64,
    /// Sender wallet pubkey.
    pub sender: Pubkey,
    /// Recipient wallet pubkey.
    pub recipient: Pubkey,
    /// Raw token amount.
    pub amount: u64,
    /// Final status of the payment.
    pub status: PaymentStatus,
    /// Unix timestamp (seconds) the receipt was issued.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// PaymentManager
// ---------------------------------------------------------------------------

/// Stateless helper that creates, confirms, rejects, parses, and batches
/// chat-attached payments.
pub struct PaymentManager {
    /// Token mint all payments are denominated in.
    token_mint: Pubkey,
}

impl PaymentManager {
    /// Create a new manager bound to a specific token mint.
    pub fn new(token_mint: Pubkey) -> Self {
        Self { token_mint }
    }

    /// The configured token mint.
    pub fn token_mint(&self) -> Pubkey {
        self.token_mint
    }

    /// Attach a payment request to a chat message.
    ///
    /// The returned [`PaymentMessage`] is in [`PaymentStatus::Pending`] state
    /// (the `tx_signature` is empty until confirmed).
    pub fn attach_payment(
        &self,
        chat_message_id: u64,
        sender: Pubkey,
        recipient: Pubkey,
        amount: u64,
        memo: String,
    ) -> PaymentMessage {
        PaymentMessage {
            sender,
            recipient,
            amount,
            token_mint: self.token_mint,
            chat_message_id,
            memo,
            tx_signature: Vec::new(),
            timestamp: now_unix(),
        }
    }

    /// Confirm a payment by recording its on-chain transaction signature.
    ///
    /// A non-empty signature is treated as verified (the actual on-chain
    /// confirmation is delegated to `TokenClient`). Returns a
    /// [`PaymentStatus::Confirmed`] receipt. An empty signature yields a
    /// [`PaymentStatus::Failed`] receipt.
    pub fn confirm_payment(
        &self,
        payment: &PaymentMessage,
        tx_signature: Vec<u8>,
    ) -> PaymentReceipt {
        let status = if tx_signature.is_empty() {
            PaymentStatus::Failed
        } else {
            PaymentStatus::Confirmed
        };
        PaymentReceipt {
            message_id: payment.chat_message_id,
            sender: payment.sender,
            recipient: payment.recipient,
            amount: payment.amount,
            status,
            timestamp: now_unix(),
        }
    }

    /// Reject a payment, returning a [`PaymentStatus::Failed`] receipt.
    pub fn reject_payment(&self, message_id: u64) -> PaymentReceipt {
        PaymentReceipt {
            message_id,
            sender: Pubkey::default(),
            recipient: Pubkey::default(),
            amount: 0,
            status: PaymentStatus::Failed,
            timestamp: now_unix(),
        }
    }

    /// Parse a payment request out of a chat message's text.
    ///
    /// Recognised forms:
    /// - `💸 5.00 EPS`        — inline tip to the chat counterpart
    /// - `💰 send 10 EPS to @bob` — explicit send with a handle recipient
    ///
    /// Returns `None` if no payment emoji/keyword is found or the amount
    /// cannot be parsed.
    pub fn parse_payment_from_message(&self, chat_text: &str) -> Option<PaymentMessage> {
        let text = chat_text.trim();

        // Form 1: "💸 5.00 EPS"  (also accept 💰 emoji prefix without "send")
        // Form 2: "💰 send 10 EPS to @bob"
        let has_money_emoji = text.contains('💸') || text.contains('💰');
        if !has_money_emoji {
            return None;
        }

        // Strip the leading emoji(s) and optional "send" keyword to get to the
        // numeric amount.
        let after_emoji = text
            .trim_start_matches(|c: char| c == '💸' || c == '💰')
            .trim();

        // Optional "send " prefix.
        let after_send = after_emoji
            .strip_prefix("send ")
            .or_else(|| after_emoji.strip_prefix("Send "))
            .unwrap_or(after_emoji)
            .trim();

        // The amount is the leading numeric token (integer or decimal).
        let amount_token = after_send.split_whitespace().next()?;
        let ui_amount: f64 = amount_token.parse().ok()?;
        if !(ui_amount > 0.0) {
            return None;
        }

        // Expect the symbol (EPS) to follow the amount.
        let mut tokens = after_send.split_whitespace();
        tokens.next(); // amount
        let symbol_token = tokens.next();
        let symbol_ok = match symbol_token {
            Some(s) => s.eq_ignore_ascii_case(EPSILON_TOKEN_SYMBOL),
            None => false,
        };
        if !symbol_ok {
            return None;
        }

        // Optional recipient handle ("to @bob") — we don't resolve handles
        // here; the caller wires the parsed message to a real Pubkey. Use a
        // default placeholder recipient.
        let raw_amount = (ui_amount * 10f64.powi(EPSILON_TOKEN_DECIMALS as i32)) as u64;

        Some(PaymentMessage {
            sender: Pubkey::default(),
            recipient: Pubkey::default(),
            amount: raw_amount,
            token_mint: self.token_mint,
            chat_message_id: 0,
            memo: text.to_string(),
            tx_signature: Vec::new(),
            timestamp: now_unix(),
        })
    }

    /// Format a receipt for UI display inside a chat bubble.
    ///
    /// Example: `💰 5.00 EPS received from <sender_short>`
    pub fn format_payment_bubble(&self, receipt: &PaymentReceipt) -> String {
        let ui = format_ui_amount(receipt.amount);
        let sender_short = short_pubkey(&receipt.sender);
        match receipt.status {
            PaymentStatus::Confirmed => {
                format!(
                    "💰 {} {} received from {}",
                    ui, EPSILON_TOKEN_SYMBOL, sender_short
                )
            }
            PaymentStatus::Pending => {
                format!(
                    "⏳ {} {} pending from {}",
                    ui, EPSILON_TOKEN_SYMBOL, sender_short
                )
            }
            PaymentStatus::Failed => {
                format!(
                    "❌ {} {} from {} failed",
                    ui, EPSILON_TOKEN_SYMBOL, sender_short
                )
            }
        }
    }

    /// Produce a deterministic SHA-256 batch hash over a set of receipts,
    /// suitable as a leaf in the mesh Merkle settlement tree.
    ///
    /// The digest covers, for each receipt in order:
    /// `message_id || sender || recipient || amount || status_byte || timestamp`
    /// all in little-endian / fixed-width form. The final hash is returned as
    /// a 32-byte `Vec<u8>`.
    pub fn batch_payments(&self, receipts: Vec<PaymentReceipt>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for r in &receipts {
            hasher.update(r.message_id.to_le_bytes());
            hasher.update(r.sender.to_bytes());
            hasher.update(r.recipient.to_bytes());
            hasher.update(r.amount.to_le_bytes());
            hasher.update([status_byte(r.status)]);
            hasher.update(r.timestamp.to_le_bytes());
        }
        let digest = hasher.finalize();
        digest.to_vec()
    }
}

/// Map a [`PaymentStatus`] to a single deterministic byte for hashing.
fn status_byte(s: PaymentStatus) -> u8 {
    match s {
        PaymentStatus::Pending => 0,
        PaymentStatus::Confirmed => 1,
        PaymentStatus::Failed => 2,
    }
}

/// Short, human-friendly rendering of a Pubkey (first 6 base58-ish chars).
fn short_pubkey(pk: &Pubkey) -> String {
    let s = pk.to_string();
    let len = s.len().min(8);
    format!("{}…", &s[..len])
}

// ---------------------------------------------------------------------------
// PaymentLedger
// ---------------------------------------------------------------------------

/// In-memory ledger of settled payment receipts, indexed by chat message id.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PaymentLedger {
    /// All settled receipts, in insertion order.
    pub payments: Vec<PaymentReceipt>,
}

impl PaymentLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a receipt to the ledger.
    pub fn add(&mut self, receipt: PaymentReceipt) {
        self.payments.push(receipt);
    }

    /// Look up a receipt by the chat message id it was attached to.
    pub fn get_by_chat_message(&self, message_id: u64) -> Option<&PaymentReceipt> {
        self.payments.iter().find(|r| r.message_id == message_id)
    }

    /// Total raw amount sent by `sender` across all confirmed receipts.
    pub fn total_sent(&self, sender: &Pubkey) -> u64 {
        self.payments
            .iter()
            .filter(|r| &r.sender == sender && r.status == PaymentStatus::Confirmed)
            .map(|r| r.amount)
            .sum()
    }

    /// Total raw amount received by `recipient` across all confirmed receipts.
    pub fn total_received(&self, recipient: &Pubkey) -> u64 {
        self.payments
            .iter()
            .filter(|r| &r.recipient == recipient && r.status == PaymentStatus::Confirmed)
            .map(|r| r.amount)
            .sum()
    }

    /// Net balance for `account`: total received minus total sent.
    pub fn balance_for(&self, account: &Pubkey) -> u64 {
        // Subtraction saturates at zero — a wallet can't go negative in this
        // ledger's view.
        self.total_received(account)
            .saturating_sub(self.total_sent(account))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mint() -> Pubkey {
        Pubkey::new_unique()
    }

    fn alice() -> Pubkey {
        Pubkey::new_unique()
    }

    fn bob() -> Pubkey {
        Pubkey::new_unique()
    }

    fn raw(ui: f64) -> u64 {
        (ui * 10f64.powi(EPSILON_TOKEN_DECIMALS as i32)) as u64
    }

    // 1. attach_payment creates a valid PaymentMessage --------------------------------
    #[test]
    fn test_attach_payment_creates_valid_message() {
        let mgr = PaymentManager::new(mint());
        let (a, b) = (alice(), bob());
        let msg = mgr.attach_payment(42, a, b, raw(5.0), "coffee".to_string());

        assert_eq!(msg.sender, a);
        assert_eq!(msg.recipient, b);
        assert_eq!(msg.amount, raw(5.0));
        assert_eq!(msg.token_mint, mgr.token_mint());
        assert_eq!(msg.chat_message_id, 42);
        assert_eq!(msg.memo, "coffee");
        assert!(msg.tx_signature.is_empty(), "pending message has no tx sig");
        assert!(msg.timestamp > 0);
    }

    // 2. confirm_payment returns Confirmed status -------------------------------------
    #[test]
    fn test_confirm_payment_confirmed() {
        let mgr = PaymentManager::new(mint());
        let (a, b) = (alice(), bob());
        let msg = mgr.attach_payment(7, a, b, raw(3.5), "lunch".into());
        let sig = vec![1u8, 2, 3, 4];
        let receipt = mgr.confirm_payment(&msg, sig.clone());

        assert_eq!(receipt.message_id, 7);
        assert_eq!(receipt.sender, a);
        assert_eq!(receipt.recipient, b);
        assert_eq!(receipt.amount, raw(3.5));
        assert_eq!(receipt.status, PaymentStatus::Confirmed);
    }

    // 3. reject_payment returns Failed status -----------------------------------------
    #[test]
    fn test_reject_payment_failed() {
        let mgr = PaymentManager::new(mint());
        let receipt = mgr.reject_payment(99);

        assert_eq!(receipt.message_id, 99);
        assert_eq!(receipt.status, PaymentStatus::Failed);
        assert_eq!(receipt.amount, 0);
    }

    // 3b. confirm with empty signature fails ------------------------------------------
    #[test]
    fn test_confirm_payment_empty_sig_fails() {
        let mgr = PaymentManager::new(mint());
        let (a, b) = (alice(), bob());
        let msg = mgr.attach_payment(1, a, b, raw(1.0), String::new());
        let receipt = mgr.confirm_payment(&msg, Vec::new());
        assert_eq!(receipt.status, PaymentStatus::Failed);
    }

    // 4. parse "💸 5.00 EPS" -----------------------------------------------------------
    #[test]
    fn test_parse_inline_tip() {
        let mgr = PaymentManager::new(mint());
        let parsed = mgr
            .parse_payment_from_message("💸 5.00 EPS")
            .expect("should parse");
        assert_eq!(parsed.amount, raw(5.0));
        assert_eq!(parsed.token_mint, mgr.token_mint());
        assert!(parsed.memo.contains("💸"));
    }

    // 5. parse "💰 send 10 EPS to @bob" ------------------------------------------------
    #[test]
    fn test_parse_send_form() {
        let mgr = PaymentManager::new(mint());
        let parsed = mgr
            .parse_payment_from_message("💰 send 10 EPS to @bob")
            .expect("should parse");
        assert_eq!(parsed.amount, raw(10.0));
        assert_eq!(parsed.token_mint, mgr.token_mint());
    }

    // 6. no payment → None ------------------------------------------------------------
    #[test]
    fn test_parse_no_payment_returns_none() {
        let mgr = PaymentManager::new(mint());
        assert!(mgr
            .parse_payment_from_message("hey, how are you?")
            .is_none());
        assert!(mgr
            .parse_payment_from_message("send me the docs please")
            .is_none());
        assert!(
            mgr.parse_payment_from_message("10 EPS").is_none(),
            "no emoji => None"
        );
    }

    // 6b. malformed amount / symbol → None -------------------------------------------
    #[test]
    fn test_parse_malformed_returns_none() {
        let mgr = PaymentManager::new(mint());
        assert!(mgr
            .parse_payment_from_message("💸 notanumber EPS")
            .is_none());
        assert!(
            mgr.parse_payment_from_message("💸 5.00 USD").is_none(),
            "wrong symbol"
        );
        assert!(
            mgr.parse_payment_from_message("💸 0 EPS").is_none(),
            "zero amount"
        );
    }

    // 7. format_payment_bubble shows amount and sender --------------------------------
    #[test]
    fn test_format_payment_bubble() {
        let mgr = PaymentManager::new(mint());
        let a = alice();
        let receipt = PaymentReceipt {
            message_id: 1,
            sender: a,
            recipient: bob(),
            amount: raw(5.0),
            status: PaymentStatus::Confirmed,
            timestamp: 123,
        };
        let bubble = mgr.format_payment_bubble(&receipt);
        assert!(
            bubble.contains("5.00"),
            "bubble should show 5.00, got: {}",
            bubble
        );
        assert!(
            bubble.contains(EPSILON_TOKEN_SYMBOL),
            "bubble should show symbol"
        );
        assert!(bubble.contains("received"), "bubble should say received");
        // Sender short form should appear (first chars of base58 pubkey).
        let sender_str = a.to_string();
        assert!(
            bubble.contains(&sender_str[..8]),
            "bubble should include sender prefix, got: {}",
            bubble
        );
    }

    // 8. batch_payments produces consistent hash -------------------------------------
    #[test]
    fn test_batch_payments_consistent() {
        let mgr = PaymentManager::new(mint());
        let a = alice();
        let b = bob();
        let r1 = PaymentReceipt {
            message_id: 1,
            sender: a,
            recipient: b,
            amount: raw(2.0),
            status: PaymentStatus::Confirmed,
            timestamp: 100,
        };
        let r2 = PaymentReceipt {
            message_id: 2,
            sender: b,
            recipient: a,
            amount: raw(3.0),
            status: PaymentStatus::Confirmed,
            timestamp: 200,
        };
        let receipts = vec![r1.clone(), r2.clone()];
        let h1 = mgr.batch_payments(receipts.clone());
        let h2 = mgr.batch_payments(receipts);
        assert_eq!(h1.len(), 32, "SHA-256 digest is 32 bytes");
        assert_eq!(h1, h2, "same input => same hash");
    }

    // 8b. batch_payments differs when receipts differ --------------------------------
    #[test]
    fn test_batch_payments_differs() {
        let mgr = PaymentManager::new(mint());
        let a = alice();
        let b = bob();
        let r1 = PaymentReceipt {
            message_id: 1,
            sender: a,
            recipient: b,
            amount: raw(2.0),
            status: PaymentStatus::Confirmed,
            timestamp: 100,
        };
        let mut r2 = r1.clone();
        r2.amount = raw(99.0);

        let h1 = mgr.batch_payments(vec![r1]);
        let h2 = mgr.batch_payments(vec![r2]);
        assert_ne!(h1, h2, "different amounts => different hash");
    }

    // 9. ledger total_sent and total_received -----------------------------------------
    #[test]
    fn test_ledger_totals() {
        let a = alice();
        let b = bob();
        let mut ledger = PaymentLedger::new();
        ledger.add(PaymentReceipt {
            message_id: 1,
            sender: a,
            recipient: b,
            amount: raw(5.0),
            status: PaymentStatus::Confirmed,
            timestamp: 1,
        });
        ledger.add(PaymentReceipt {
            message_id: 2,
            sender: a,
            recipient: b,
            amount: raw(7.0),
            status: PaymentStatus::Confirmed,
            timestamp: 2,
        });
        // A failed payment should NOT count toward totals.
        ledger.add(PaymentReceipt {
            message_id: 3,
            sender: a,
            recipient: b,
            amount: raw(100.0),
            status: PaymentStatus::Failed,
            timestamp: 3,
        });

        assert_eq!(ledger.total_sent(&a), raw(12.0));
        assert_eq!(ledger.total_received(&b), raw(12.0));
        assert_eq!(ledger.total_sent(&b), 0);
        assert_eq!(ledger.total_received(&a), 0);
    }

    // 10. ledger balance_for calculates correctly ------------------------------------
    #[test]
    fn test_ledger_balance_for() {
        let a = alice();
        let b = bob();
        let c = Pubkey::new_unique();
        let mut ledger = PaymentLedger::new();
        // a -> b : 10
        ledger.add(PaymentReceipt {
            message_id: 1,
            sender: a,
            recipient: b,
            amount: raw(10.0),
            status: PaymentStatus::Confirmed,
            timestamp: 1,
        });
        // b -> a : 4
        ledger.add(PaymentReceipt {
            message_id: 2,
            sender: b,
            recipient: a,
            amount: raw(4.0),
            status: PaymentStatus::Confirmed,
            timestamp: 2,
        });
        // c -> a : 2  (third party inflow to a)
        ledger.add(PaymentReceipt {
            message_id: 3,
            sender: c,
            recipient: a,
            amount: raw(2.0),
            status: PaymentStatus::Confirmed,
            timestamp: 3,
        });

        // a: received (4 + 2) = 6, sent 10 => 6 - 10 saturates to 0
        assert_eq!(ledger.balance_for(&a), 0);
        // b: received 10 - sent 4 = 6
        assert_eq!(ledger.balance_for(&b), raw(6.0));
        // c: received 0 - sent 2 => saturates to 0
        assert_eq!(ledger.balance_for(&c), 0);
    }

    // 10b. get_by_chat_message --------------------------------------------------------
    #[test]
    fn test_ledger_get_by_chat_message() {
        let mut ledger = PaymentLedger::new();
        let r = PaymentReceipt {
            message_id: 77,
            sender: alice(),
            recipient: bob(),
            amount: raw(1.0),
            status: PaymentStatus::Confirmed,
            timestamp: 1,
        };
        ledger.add(r.clone());
        assert!(ledger.get_by_chat_message(77).is_some());
        assert_eq!(ledger.get_by_chat_message(77).unwrap().amount, raw(1.0));
        assert!(ledger.get_by_chat_message(999).is_none());
    }

    // 11. PaymentStatus serialization roundtrip ---------------------------------------
    #[test]
    fn test_payment_status_serde_roundtrip() {
        for s in [
            PaymentStatus::Pending,
            PaymentStatus::Confirmed,
            PaymentStatus::Failed,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: PaymentStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    // 12. PaymentMessage serialization roundtrip --------------------------------------
    #[test]
    fn test_payment_message_serde_roundtrip() {
        let mgr = PaymentManager::new(mint());
        let msg = mgr.attach_payment(5, alice(), bob(), raw(2.5), "memo".into());
        let json = serde_json::to_string(&msg).unwrap();
        let back: PaymentMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.chat_message_id, 5);
        assert_eq!(back.amount, raw(2.5));
        assert_eq!(back.memo, "memo");
    }

    // 13. format_payment_bubble for pending and failed -------------------------------
    #[test]
    fn test_format_payment_bubble_statuses() {
        let mgr = PaymentManager::new(mint());
        let base = || PaymentReceipt {
            message_id: 1,
            sender: alice(),
            recipient: bob(),
            amount: raw(5.0),
            status: PaymentStatus::Confirmed,
            timestamp: 1,
        };
        let mut r = base();
        r.status = PaymentStatus::Pending;
        assert!(mgr.format_payment_bubble(&r).contains("pending"));
        r.status = PaymentStatus::Failed;
        assert!(mgr.format_payment_bubble(&r).contains("failed"));
    }
}
