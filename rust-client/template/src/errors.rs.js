/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';

export default function ({ asyncapi, params }) {
    return (
        <File name="errors.rs">
            {`//! Error types for the NATS client

use crate::auth::AuthError;
use thiserror::Error;

/// Errors that can occur when using the NATS client
#[derive(Debug, Error)]
pub enum ClientError {
    /// NATS operation failed
    #[error("NATS operation failed: {0}")]
    Nats(Box<dyn std::error::Error + Send + Sync>),

    /// Serialization or deserialization failed
    #[error("Serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid message envelope format
    #[error("Invalid message envelope: {0}")]
    InvalidEnvelope(String),

    /// Operation timeout
    #[error("Operation timed out")]
    Timeout,

    /// No response received for request
    #[error("No response received")]
    NoResponse,

    /// Authentication error
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),

    /// Unauthorized access
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

/// Result type alias for client operations
pub type ClientResult<T> = Result<T, ClientError>;
`}
        </File>
    );
};
