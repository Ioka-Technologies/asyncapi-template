/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function MainRs({ asyncapi, _params }) {
    const info = asyncapi.info();
    const title = info.title();

    // Detect protocols from servers
    const servers = asyncapi.servers();
    const protocols = new Set();

    if (servers) {
        Object.entries(servers).forEach(([_name, server]) => {
            const protocol = server.protocol && server.protocol();
            if (protocol) {
                protocols.add(protocol.toLowerCase());
            }
        });
    }

    return (
        <File name="main.rs">
            {`#![allow(dead_code, unused_imports)]

use crate::errors::AsyncApiResult;
use tracing::{info, warn, Level};
use tracing_subscriber;
use std::env;

// Import modules
mod config;
mod server;
mod models;
mod handlers;
mod middleware;
mod errors;
mod recovery;
mod transport;
mod context;
mod router;
#[cfg(feature = "auth")]
mod auth;

use config::Config;
use server::Server;

#[tokio::main]
async fn main() -> AsyncApiResult<()> {
    // Initialize tracing with configurable level
    let log_level = env::var("LOG_LEVEL")
        .unwrap_or_else(|_| "info".to_string())
        .parse::<Level>()
        .unwrap_or(Level::INFO);

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    info!("Starting ${title} server...");
    info!("Generated from AsyncAPI specification");

    // Load configuration
    let config = Config::from_env()?;
    info!("Server configuration: {:?}", config);

    // Initialize server
    let server = Server::new(config).await?;

    // Start protocol handlers
    server.start_http_handler().await?;

    info!("Server started successfully!");
    info!("Press Ctrl+C to shutdown");

    // Keep the server running
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal");
        }
        Err(err) => {
            warn!("Unable to listen for shutdown signal: {}", err);
        }
    }

    info!("Shutting down server...");
    server.shutdown().await?;

    Ok(())
}
`}
        </File>
    );
}
