/* eslint-disable no-unused-vars */
import { File } from '@asyncapi/generator-react-sdk';
import {
    toRustIdentifier,
    toRustTypeName,
    toRustFieldName,
    toRustEnumVariant,
    toRustEnumVariantWithSerde,
    generateRustModels,
    generateMessageEnvelope
} from '../../../common/src/index.js';

export default function ModelsRs({ asyncapi }) {
    // Generate models using the common helper
    const models = generateRustModels(asyncapi, {
        toRustTypeName,
        toRustFieldName,
        toRustEnumVariantWithSerde,
        includeAsyncApiTrait: true, // Server includes the AsyncApiMessage trait
        includeEnvelope: false // We'll generate the envelope separately
    });

    // Generate the unified message envelope
    const envelopeCode = generateMessageEnvelope();

    return (
        <File name="models.rs">
            {`//! Strongly-typed message models generated from AsyncAPI specification
//!
//! This module provides type-safe message structures that ensure:
//! - **Compile-time validation**: Invalid message structures are caught at build time
//! - **Automatic serialization**: Messages are seamlessly converted to/from JSON
//! - **Schema compliance**: All messages match the AsyncAPI specification exactly
//! - **IDE support**: Full autocomplete and type checking for message fields
//!
//! ## Design Philosophy
//!
//! These models are designed to be:
//! - **Immutable by default**: Prevents accidental modification of message data
//! - **Clone-friendly**: Efficient copying for message routing and processing
//! - **Debug-enabled**: Easy troubleshooting with automatic debug formatting
//! - **Serde-compatible**: Seamless JSON serialization for transport layers
//!
//! ## Usage Patterns
//!
//! \`\`\`no-run
//! use crate::models::*;
//! use uuid::Uuid;
//! use chrono::Utc;
//!
//! // Create a new message with type safety
//! let signup_request = UserSignup {
//!     id: Uuid::new_v4(),
//!     username: "johndoe".to_string(),
//!     email: "john@example.com".to_string(),
//!     created_at: Utc::now(),
//!     // Compiler ensures all required fields are provided
//! };
//!
//! // Automatic JSON serialization
//! let json_payload = serde_json::to_string(&signup_request)?;
//!
//! // Type-safe deserialization with validation
//! let parsed_message: UserSignup = serde_json::from_str(&json_payload)?;
//! \`\`\`

${envelopeCode}
${models.generateComponentSchemas()}
${models.generateNestedTypes()}
${models.generateAsyncApiTrait()}

${models.messageSchemas.length === 0 ? `
/// Example message structure when no messages are defined in the spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleMessage {
    pub id: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
}

impl AsyncApiMessage for ExampleMessage {
    fn message_type(&self) -> &'static str {
        "example"
    }

    fn channel(&self) -> &'static str {
        "example/channel"
    }
}` : ''}
`}
        </File>
    );
}
