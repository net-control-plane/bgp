use std::net::IpAddr;

use bgp_packet::nlri::NLRI;
use clap::{Parser, Subcommand};
use eyre::{bail, Result};
use route_client::netlink::NetlinkConnector;
use route_client::southbound_interface::SouthboundInterface;
use tracing::info;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[clap(
    author = "Rayhaan Jaufeerally <rayhaan@rayhaan.ch>",
    version = "0.1",
    about = "Misc routing utilities"
)]
struct Cli {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// AddRoute installs the routes received into the kernel routing table.
    AddRoute {
        /// The destination IP prefix.
        prefix: String,
        /// The next hop for sending traffic to the prefix.
        nexthop: String,
        /// Table to add route into.
        #[arg(default_value_t = 201)]
        rt_table: u32,
    },
    /// DelRoute installs the routes received into the kernel routing table.
    DelRoute {
        /// The destination IP prefix.
        prefix: String,
        /// The next hop for sending traffic to the prefix.
        nexthop: String,
        /// Table to add route into.
        #[arg(default_value_t = 201)]
        rt_table: u32,
    },
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
        Some(Commands::AddRoute {
            prefix,
            nexthop,
            rt_table,
        }) => {
            let mut handle = NetlinkConnector::new(Some(rt_table)).await?;
            let prefix: NLRI = NLRI::try_from(prefix.as_str())?;
            let nexthop: IpAddr = nexthop.parse()?;
            handle.route_add(prefix.afi, prefix, nexthop).await?;
        }
        Some(Commands::DelRoute {
            prefix,
            nexthop,
            rt_table,
        }) => {
            let mut handle = NetlinkConnector::new(Some(rt_table)).await?;
            let prefix: NLRI = NLRI::try_from(prefix.as_str())?;
            let nexthop: IpAddr = nexthop.parse()?;
            handle.route_del(prefix, nexthop).await?;
        }
        None => bail!("A subcommand must be specified."),
    };

    Ok(())
}
