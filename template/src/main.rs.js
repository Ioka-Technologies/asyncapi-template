import { File } from '@asyncapi/generator-react-sdk';
import { kebabCase } from '../helpers/index';

export default function mainFile({ asyncapi, params }) {
    const packageName = params.packageName || kebabCase(asyncapi.info().title()) || 'asyncapi_client';
    const libName = packageName.replace(/-/g, '_');
    const useAsyncStd = params.useAsyncStd || false;
    const runtime = useAsyncStd ? 'async_std' : 'tokio';

    return (
        <File name="src/main.rs">
            {`//! Example main function for the AsyncAPI client

use ${libName}::{Client, Config};
use log::{error, info};

#[${runtime === 'tokio' ? 'tokio::main' : 'async_std::main'}]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    info!("Starting ${asyncapi.info().title()} client");

    // Create and configure the client
    let mut client = Client::new().await?;

    // Start the client
    client.start().await?;

    info!("Client started successfully");

    // Keep the application running
    // In a real application, you would handle shutdown signals here
    ${runtime === 'tokio' ? 'tokio::signal::ctrl_c().await?;' : 'async_std::task::sleep(std::time::Duration::from_secs(3600)).await;'}

    info!("Shutting down client");
    client.stop().await?;

    Ok(())
}
`}
        </File>
    );
}
