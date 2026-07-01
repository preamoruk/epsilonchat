//! EpsilonChat — Mesh-stored Merkle tree for Solana ZK Compression
//!
//! Replaces centralized Photon Indexer with P2P mesh distribution
//! of Merkle tree leaves via Iroh gossip + DHT.

pub mod leaf_store;
pub mod tree_replica;
pub mod mesh_indexer;
pub mod proof_provider;
pub mod proof_requester;
pub mod gossip;
pub mod web_ui;
pub mod relay_mining;
pub mod relay_settlement;
pub mod solana_zk;
pub mod vrf_sortition;
pub mod validator;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "epsilon-merkle")]
#[command(about = "EpsilonChat mesh-stored Merkle tree indexer")]
struct Cli {
    /// Solana RPC URL (default: devnet)
    #[arg(long, default_value = "https://api.devnet.solana.com")]
    rpc: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as desktop forester: full tree, serve proofs, broadcast leaves
    Forester {
        /// Merkle tree pubkey to index (base58)
        #[arg(long)]
        tree: String,

        /// Iroh data directory
        #[arg(long, default_value = "./.epsilon/forester")]
        data_dir: String,
    },

    /// Run as phone client: store only own leaf, request proofs
    Phone {
        /// Your Solana pubkey (base58) — only leaves owned by this key are stored
        #[arg(long)]
        owner: String,

        /// Iroh data directory
        #[arg(long, default_value = "./.epsilon/phone")]
        data_dir: String,
    },

    /// Generate an invite link for peer connection
    Invite,

    /// Connect to a peer via invite link
    Connect {
        /// Invite link (iroh://...)
        link: String,
    },

    /// Launch web UI (opens HTTP server with interactive dashboard)
    Web {
        /// Port for web UI (default: 8848)
        #[arg(long, default_value = "8848")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "epsilon_merkle=info,iroh=warn".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Forester { tree, data_dir } => {
            crate::mesh_indexer::run_forester(&cli.rpc, &tree, &data_dir).await
        }
        Command::Phone { owner, data_dir } => {
            crate::proof_requester::run_phone(&cli.rpc, &owner, &data_dir).await
        }
        Command::Invite => {
            crate::gossip::generate_invite().await
        }
        Command::Connect { link } => {
            crate::gossip::connect_via_invite(&link).await
        }
        Command::Web { port } => {
            crate::web_ui::run_web_ui(port).await
        }
    }
}