use clap::Parser;
use eyre::Result;
use tracing::{info, warn};

use route_client::netlink::NetlinkConnector;
use route_client::{run_connector_v4, run_connector_v6};

#[derive(Parser)]
#[clap(
    author = "Rayhaan Jaufeerally <rayhaan@rayhaan.ch>",
    version = "0.1",
    about = "Installs routes from a BGP speaker via streaming RPC to the forwarding plane"
)]
struct Cli {
    #[clap(long = "route_server")]
    route_server: String,
    #[clap(long = "rt_table")]
    rt_table: Option<u32>,
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    tracing_subscriber::fmt().pretty().init();

    info!("Starting route client");

    let rt_table = match args.rt_table {
        Some(table) => table,
        None => 201,
    };

    let v4_joinhandle = {
        let server_addr = args.route_server.clone();
        tokio::task::spawn(async move {
            run_connector_v4::<NetlinkConnector>(
                server_addr.clone(),
                rt_table,
                args.dry_run,
                NetlinkConnector::new(Some(rt_table)).await.unwrap(),
            )
            .await
            .unwrap();
        })
    };

    let v6_joinhandle = {
        let server_addr = args.route_server.clone();
        tokio::task::spawn(async move {
            run_connector_v6::<NetlinkConnector>(
                server_addr,
                rt_table,
                args.dry_run,
                NetlinkConnector::new(Some(rt_table)).await.unwrap(),
            )
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

    Ok(())
}
