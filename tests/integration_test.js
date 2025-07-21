import { File } from '@asyncapi/generator-react-sdk';
import { kebabCase } from '../helpers/index';

export default function integrationTestFile({ asyncapi, params }) {
    const packageName = params.packageName || kebabCase(asyncapi.info().title()) || 'asyncapi_client';
    const libName = packageName.replace(/-/g, '_');
    const useAsyncStd = params.useAsyncStd || false;
    const runtime = useAsyncStd ? 'async_std' : 'tokio';

    return (
        <File name="tests/integration_test.rs">
            {`//! Integration tests for the AsyncAPI client

use ${libName}::{Client, Config};

#[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
async fn test_client_creation() {
    let config = Config::default();
    let client = Client::new_with_config(config);

    assert!(!client.is_connected().await);
}

#[${runtime === 'tokio' ? 'tokio::test' : 'async_std::test'}]
async fn test_config_loading() {
    let config = Config::from_env();

    // Test that default values are set
    assert_eq!(config.server.timeout, 30);
    assert_eq!(config.server.max_retries, 3);
}

#[test]
fn test_version_constants() {
    assert!(!${libName}::VERSION.is_empty());
    assert!(!${libName}::ASYNCAPI_VERSION.is_empty());
    assert!(!${libName}::PROTOCOL.is_empty());
}

// Add more integration tests here based on your specific use case
`}
        </File>
    );
}
