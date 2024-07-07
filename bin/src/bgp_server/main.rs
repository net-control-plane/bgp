// Copyright 2021 Rayhaan Jaufeerally.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bgp_server::bgp_server::Server;
use bgp_server::config::ServerConfig;
use clap::{App, Arg};
use core::sync::atomic::AtomicBool;
use libc::SIGUSR1;
use signal_hook::consts::signal::*;
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::flag;
use signal_hook::iterator::exfiltrator::WithOrigin;
use signal_hook::iterator::SignalsInfo;
use std::fs::File;
use std::io::BufReader;
use std::process::exit;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = tracing_subscriber::fmt().with_env_filter("bgpd=info");

    match subscriber.try_init() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Failed to initialize logger: {:?}", e);
            exit(1);
        }
    }

    let argv_matches = App::new("bgpd")
        .author("Rayhaan Jaufeerally <rayhaan@rayhaan.ch>")
        .version("0.1")
        .about("net-control-plane BGP daemon")
        .arg(Arg::with_name("config").takes_value(true))
        .get_matches();

    info!("Starting BGP Daemon!");

    let config_file = File::open(argv_matches.value_of("config").unwrap_or("config.json")).unwrap();
    let reader = BufReader::new(config_file);
    let server_config: ServerConfig = serde_json::from_reader(reader).unwrap();

    info!("Parsed server config");

    let mut bgp_server = Server::new(server_config);
    bgp_server.start(true).await.unwrap();

    // The following signal handling code is from:
    // https://docs.rs/signal-hook/0.3.10/signal_hook/
    // Comments removed for brevity.
    let term_now = Arc::new(AtomicBool::new(false));
    for sig in TERM_SIGNALS {
        flag::register_conditional_shutdown(*sig, 1, Arc::clone(&term_now))?;
        flag::register(*sig, Arc::clone(&term_now))?;
    }

    let mut sigs = vec![SIGHUP, SIGUSR1];
    sigs.extend(TERM_SIGNALS);
    let mut signals = SignalsInfo::<WithOrigin>::new(&sigs)?;

    for info in &mut signals {
        match info.signal {
            // TODO: Implement something on receiving SIGHUP / SIGUSR1.
            SIGHUP => {
                println!("Caught SIGHUP, not doing anything");
            }
            SIGUSR1 => {
                println!("Caught SIGUSR1, not doing anything");
            }
            _term_sig => {
                eprintln!("Shutting down app");
                break;
            }
        }
    }

    bgp_server.shutdown().await;

    Ok(())
}
