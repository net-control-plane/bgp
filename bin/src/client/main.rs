use bgp_packet::constants::AddressFamilyIdentifier;
use clap::{Parser, Subcommand};
use eyre::{bail, Result};
use route_client::southbound_interface::{DummyVerifier, SouthboundInterface};
use tracing::{info, warn};

use route_client::netlink::NetlinkConnector;
use route_client::{run_connector_v4, run_connector_v6};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[clap(
    author = "Rayhaan Jaufeerally <rayhaan@rayhaan.ch>",
    version = "0.1",
    about = "Installs routes from a BGP speaker via streaming RPC to the forwarding plane"
)]
struct Cli {
    /// route_server is the gRPC endpoint to connect to for streaming routes from.
    #[clap(long = "route_server")]
    route_server: String,
    #[clap(subcommand)]
    command: Option<Commands>,
    #[clap(long = "af")]
    address_family: Vec<AddressFamilyIdentifier>,
}

#[derive(Subcommand)]
enum Commands {
    /// InstallKernel installs the routes received into the kernel routing table.
    InstallKernel {
        #[arg(default_value_t = 201)]
        rt_table: u32,
        #[arg(default_value_t = false)]
        dry_run: bool,
    },
    /// Verify performs consistency checks on the inbound stream of routes to ensure
    /// that there are no spurious removals or duplicate entries.
    Verify,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("Starting route client");

    match args.command {
        Some(Commands::InstallKernel { rt_table, dry_run }) => {
            let southbound = NetlinkConnector::new(Some(rt_table)).await?;
            run_connector::<NetlinkConnector>(args.route_server, dry_run, southbound).await
        }
        Some(Commands::Verify) => {
            let southbound = DummyVerifier::default();
            run_connector::<DummyVerifier>(args.route_server, false, southbound).await
        }
        None => bail!("A subcommand must be specified."),
    };

    Ok(())
}

async fn run_connector<S: SouthboundInterface + Clone + Send + Sync + 'static>(
    server_addr: String,
    dry_run: bool,
    southbound: S,
) {
    let v4_joinhandle = {
        let server_addr = server_addr.clone();
        let southbound = southbound.clone();
        tokio::task::spawn(async move {
            run_connector_v4::<S>(server_addr.clone(), dry_run, southbound)
                .await
                .unwrap();
        })
    };

    let v6_joinhandle = {
        let server_addr = server_addr.clone();
        tokio::task::spawn(async move {
            run_connector_v6::<S>(server_addr, dry_run, southbound)
                .await
                .unwrap();
        })
    };

    tokio::select! {
        _ = v4_joinhandle => {
            warn!("Unexpected exit of IPv4 connector");
        },
        _ = v6_joinhandle => {
            warn!("Unexpected exit of IPv6 connector");
        }
    }
}
