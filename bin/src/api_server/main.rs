use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use bgp_packet::nlri::NLRI;
use clap::{Parser, Subcommand};
use eyre::{bail, Result};
use route_client::connector::Connector;
use tokio::sync::Mutex;
use tracing::info;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[clap(
    author = "Rayhaan Jaufeerally <rayhaan@rayhaan.ch>",
    version = "0.1",
    about = "API Server"
)]
struct Cli {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run runs the API server connected to a given gRPC backend.
    Run {
        /// The route server gRPC backend.
        backend: String,
    },
}

struct AppState {
    pub connector: Connector,
}

async fn handle_announce(
    State(state): State<Arc<Mutex<AppState>>>,
    Path((prefix, prefixlen)): Path<(String, u8)>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    state
        .lock()
        .await
        .connector
        .send_announce(
            "pr01_rue_rayhaan_net".to_owned(),
            NLRI::try_from(format!("{}/{}", prefix, prefixlen).as_str()).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("failed to parse NLRI: {}", e),
                )
            })?,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to make RPC to backend: {}", e),
            )
        })?;
    Ok((StatusCode::OK, "Success".to_owned()))
}

async fn handle_withdraw(
    State(state): State<Arc<Mutex<AppState>>>,
    Path((prefix, prefixlen)): Path<(String, u8)>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    state
        .lock()
        .await
        .connector
        .send_withdraw(
            "pr01_rue_rayhaan_net".to_owned(),
            NLRI::try_from(format!("{}/{}", prefix, prefixlen).as_str()).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("failed to parse NLRI: {}", e),
                )
            })?,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to make RPC to backend: {}", e),
            )
        })?;
    Ok((StatusCode::OK, "Success".to_owned()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("Starting API Server");

    match args.command {
        Some(Commands::Run { backend }) => {
            let connector = Connector::new(backend).await?;
            let app = Router::new()
                .route("/announce/:prefix/:prefixlen", post(handle_announce))
                .route("/withdraw/:prefix/:prefixlen", post(handle_withdraw))
                .with_state(Arc::new(Mutex::new(AppState { connector })));

            let listener = tokio::net::TcpListener::bind("localhost:8179")
                .await
                .unwrap();
            axum::serve(listener, app).await.unwrap();
        }
        None => bail!("A subcommand must be specified."),
    };

    Ok(())
}
