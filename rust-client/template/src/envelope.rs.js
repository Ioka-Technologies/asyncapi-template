/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import { generateMessageEnvelope } from '../../../common/src/index.js';

export default function ({ asyncapi, params }) {
    // Generate the unified message envelope with error support
    const envelopeCode = generateMessageEnvelope();

    return (
        <File name="envelope.rs">
            {`//! Message envelope for consistent NATS message format

use crate::auth::{AuthCredentials, generate_auth_headers};
${envelopeCode}

// Client-specific extensions for auth integration
impl MessageEnvelope {
    /// Create a new message envelope with authentication headers
    pub fn new_with_auth<T: Serialize>(
        operation: &str,
        payload: T,
        auth: &AuthCredentials,
    ) -> Result<Self, serde_json::Error> {
        let auth_headers = generate_auth_headers(auth);
        Self::new(operation, payload).map(|envelope| envelope.with_auth_headers(auth_headers))
    }
}
`}
        </File>
    );
};
