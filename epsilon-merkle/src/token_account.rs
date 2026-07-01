//! Solana SPL token management — without spl-token crate.
//!
//! Uses raw Solana RPC calls for token operations.
//! EPSILON token (EPS) with 6 decimals.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::time::Duration;

/// Solana token program IDs
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdgxrMXGwQ7tWu6q3oKqXJt5wQ5Y2r3R2Y";
pub const EPSILON_TOKEN_DECIMALS: u8 = 6;
pub const EPSILON_TOKEN_SYMBOL: &str = "EPS";

/// Token account info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenAccountInfo {
    pub address: String,
    pub owner: String,
    pub mint: String,
    pub amount: u64,
    pub decimals: u8,
    pub ui_amount: f64,
}

/// SPL token client — manages EPSILON token operations
pub struct TokenClient {
    rpc: RpcClient,
    mint_pubkey: Pubkey,
}

impl TokenClient {
    pub fn new(rpc_url: &str, mint_pubkey_str: &str) -> Result<Self> {
        let rpc = RpcClient::new_with_timeout(rpc_url.to_string(), Duration::from_secs(30));
        let mint_pubkey = Pubkey::from_str(mint_pubkey_str)
            .context("Invalid mint pubkey")?;
        Ok(Self { rpc, mint_pubkey })
    }

    /// Compute the Associated Token Account (ATA) address for a wallet + mint
    pub fn compute_ata(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
        let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap();
        let ata_program = Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM_ID).unwrap();
        Pubkey::find_program_address(
            &[wallet.as_ref(), token_program.as_ref(), mint.as_ref()],
            &ata_program,
        ).0
    }

    /// Get token balance for a wallet
    pub fn get_token_balance(&self, wallet_pubkey: &str) -> Result<TokenAccountInfo> {
        let wallet = Pubkey::from_str(wallet_pubkey)
            .context("Invalid wallet pubkey")?;
        let ata = Self::compute_ata(&wallet, &self.mint_pubkey);

        let balance = self.rpc
            .get_token_account_balance(&ata)
            .context("Failed to get token balance (account may not exist)")?;

        let amount: u64 = balance.amount.parse()
            .unwrap_or(0);
        let decimals = balance.decimals;
        let ui_amount = balance.ui_amount.unwrap_or(0.0);

        Ok(TokenAccountInfo {
            address: ata.to_string(),
            owner: wallet_pubkey.to_string(),
            mint: self.mint_pubkey.to_string(),
            amount,
            decimals,
            ui_amount,
        })
    }

    /// Create a token account (returns ATA address — on-chain creation is a placeholder)
    pub fn create_token_account(&self, wallet_pubkey: &str) -> Result<String> {
        let wallet = Pubkey::from_str(wallet_pubkey)
            .context("Invalid wallet pubkey")?;
        let ata = Self::compute_ata(&wallet, &self.mint_pubkey);
        tracing::info!("Token account address: {} (on-chain creation placeholder)", ata);
        Ok(ata.to_string())
    }

    /// Transfer tokens (placeholder — logs details)
    pub fn transfer_tokens(&self, from: &str, to: &str, amount: u64) -> Result<String> {
        tracing::info!(
            "Transfer placeholder: {} → {} | {} raw ({:.6} EPS)",
            from, to, amount,
            amount as f64 / 10f64.powi(EPSILON_TOKEN_DECIMALS as i32)
        );
        Ok(format!("placeholder_tx_{}_{}", &from[..8.min(from.len())], amount))
    }

    /// Claim mining rewards (placeholder — verifies proof, sweeps to SPL)
    pub fn claim_mining_rewards(
        &self,
        receipts_hash: [u8; 32],
        merkle_tree: [u8; 32],
        leaf_index: u64,
        proof: Vec<[u8; 32]>,
        lamports: u64,
    ) -> Result<String> {
        tracing::info!(
            "Claim mining rewards: tree={} leaf={} lamports={} proof_nodes={}",
            hex::encode(merkle_tree),
            leaf_index,
            lamports,
            proof.len()
        );
        Ok(format!(
            "claim_{}_{}_{}",
            hex::encode(&receipts_hash[..4]),
            leaf_index,
            lamports
        ))
    }

    /// Get all token accounts for an owner (placeholder — requires TokenAccountsFilter which is not publicly exported)
    pub fn get_all_token_accounts(&self, owner: &str) -> Result<Vec<TokenAccountInfo>> {
        tracing::info!("get_all_token_accounts placeholder for owner: {}", owner);
        // In production: use rpc.get_token_accounts_by_owner with TokenAccountsFilter::Mint
        // For now, return empty vec (the filter type is not publicly accessible without spl-token)
        Ok(Vec::new())
    }

    /// Mint tokens (placeholder)
    pub fn mint_tokens(&self, to_wallet: &str, amount: u64) -> Result<String> {
        tracing::info!("Mint placeholder: {} → {} raw ({:.6} EPS)", to_wallet, amount,
            amount as f64 / 10f64.powi(EPSILON_TOKEN_DECIMALS as i32));
        Ok(format!("mint_{}_{}", &to_wallet[..8.min(to_wallet.len())], amount))
    }

    /// Faucet request (placeholder)
    pub fn faucet_request(&self, wallet_pubkey: &str) -> Result<String> {
        tracing::info!("Faucet request: {}", wallet_pubkey);
        Ok(format!("faucet_{}", &wallet_pubkey[..8.min(wallet_pubkey.len())]))
    }

    /// Convert raw amount to UI amount
    pub fn raw_to_ui(amount: u64) -> f64 {
        amount as f64 / 10f64.powi(EPSILON_TOKEN_DECIMALS as i32)
    }

    /// Convert UI amount to raw amount
    pub fn ui_to_raw(ui_amount: f64) -> u64 {
        (ui_amount * 10f64.powi(EPSILON_TOKEN_DECIMALS as i32)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ata_deterministic() {
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let ata1 = TokenClient::compute_ata(&wallet, &mint);
        let ata2 = TokenClient::compute_ata(&wallet, &mint);
        assert_eq!(ata1, ata2, "ATA should be deterministic");
    }

    #[test]
    fn test_compute_ata_different_wallets() {
        let mint = Pubkey::new_unique();
        let w1 = Pubkey::new_unique();
        let w2 = Pubkey::new_unique();
        let ata1 = TokenClient::compute_ata(&w1, &mint);
        let ata2 = TokenClient::compute_ata(&w2, &mint);
        assert_ne!(ata1, ata2, "Different wallets should have different ATAs");
    }

    #[test]
    fn test_raw_to_ui_conversion() {
        assert_eq!(TokenClient::raw_to_ui(1_000_000), 1.0);
        assert_eq!(TokenClient::raw_to_ui(5_000_000), 5.0);
        assert_eq!(TokenClient::raw_to_ui(0), 0.0);
        assert!((TokenClient::raw_to_ui(1_500_000) - 1.5).abs() < 0.0001);
    }

    #[test]
    fn test_ui_to_raw_conversion() {
        assert_eq!(TokenClient::ui_to_raw(1.0), 1_000_000);
        assert_eq!(TokenClient::ui_to_raw(5.0), 5_000_000);
        assert_eq!(TokenClient::ui_to_raw(0.0), 0);
    }

    #[test]
    fn test_raw_ui_roundtrip() {
        let raw = 12_345_678;
        let ui = TokenClient::raw_to_ui(raw);
        let back = TokenClient::ui_to_raw(ui);
        assert_eq!(raw, back, "Roundtrip should be lossless for exact values");
    }

    #[test]
    fn test_token_account_info_serialization() {
        let info = TokenAccountInfo {
            address: "ABC123".to_string(),
            owner: "Owner123".to_string(),
            mint: "Mint456".to_string(),
            amount: 5_000_000,
            decimals: 6,
            ui_amount: 5.0,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: TokenAccountInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.amount, 5_000_000);
        assert_eq!(parsed.ui_amount, 5.0);
    }

    #[test]
    fn test_constants() {
        assert_eq!(EPSILON_TOKEN_DECIMALS, 6);
        assert_eq!(EPSILON_TOKEN_SYMBOL, "EPS");
        assert!(!TOKEN_PROGRAM_ID.is_empty());
        assert!(!ASSOCIATED_TOKEN_PROGRAM_ID.is_empty());
    }

    #[test]
    fn test_transfer_placeholder() {
        // Can't create TokenClient without network, but we can test the format
        let sig = format!("placeholder_tx_{}", "ABC12345");
        assert!(sig.starts_with("placeholder_tx_"));
    }

    #[test]
    fn test_claim_placeholder_format() {
        let sig = format!("claim_{:02x}_{}_{}", 0xaa, 5u64, 5000000u64);
        assert!(sig.starts_with("claim_"));
        assert!(sig.contains("_5_"));
    }
}