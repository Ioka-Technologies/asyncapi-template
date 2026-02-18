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
        includeAsyncApiTrait: false, // Client doesn't need the AsyncApiMessage trait
        includeEnvelope: false // We'll generate the envelope separately
    });

    // Generate the unified message envelope
    const envelopeCode = generateMessageEnvelope();

    return (
        <File name="models.rs">
            {`//! Generated data models from AsyncAPI specification

${envelopeCode}
${models.generateComponentSchemas()}
${models.generateNestedTypes()}
${(() => {
                    // Track which types have already had implementations generated
                    const implementedTypes = new Set();
                    const implementations = [];

                    models.messageSchemas.forEach(schema => {
                        const doc = schema.description ? `/// ${schema.description}` : `/// ${schema.name} message`;

                        // Skip if already implemented
                        if (implementedTypes.has(schema.rustName)) {
                            return;
                        }

                        // Check if the message payload references a component schema
                        let payloadSchemaName = null;
                        let payloadSchema = null;

                        if (schema.rawPayload && schema.rawPayload.$ref) {
                            payloadSchemaName = schema.rawPayload.$ref.split('/').pop();
                        } else if (schema.payload && schema.payload.$ref) {
                            payloadSchemaName = schema.payload.$ref.split('/').pop();
                        } else if (schema.payload && schema.payload['x-parser-schema-id']) {
                            // Handle resolved $ref references
                            const schemaId = schema.payload['x-parser-schema-id'];
                            if (models.schemaRegistry.has(schemaId)) {
                                payloadSchemaName = schemaId;
                            }
                        }

                        // If we have a payload schema reference, resolve it and flatten the fields
                        // The message type should use the MESSAGE name (e.g., BootstrapDeviceRequest),
                        // NOT the payload schema name (e.g., BootstrapDevicePayload)
                        if (payloadSchemaName && models.schemaRegistry.has(payloadSchemaName)) {
                            payloadSchema = models.schemaRegistry.get(payloadSchemaName);

                            // Follow $ref chains - if the schema is just a $ref, resolve it
                            // This handles cases like: ConfigureDeviceResponsePayload: { $ref: 'common.yaml#/BaseResponse' }
                            while (payloadSchema && payloadSchema.$ref && !payloadSchema.properties && !payloadSchema.allOf) {
                                const refName = payloadSchema.$ref.split('/').pop();
                                if (models.schemaRegistry.has(refName)) {
                                    payloadSchema = models.schemaRegistry.get(refName);
                                } else {
                                    // Can't resolve further, break
                                    break;
                                }
                            }
                        }

                        implementedTypes.add(schema.rustName);

                        // Generate the message struct with flattened payload fields
                        let fields;
                        if (payloadSchema) {
                            // Use the resolved payload schema to generate fields
                            fields = models.generateMessageStruct(payloadSchema, schema.rustName);
                        } else if (schema.payload) {
                            // Fallback to the parsed payload
                            fields = models.generateMessageStruct(schema.payload, schema.rustName);
                        } else {
                            // No payload - generate empty struct with data field
                            fields = '    pub data: serde_json::Value,';
                        }

                        implementations.push(`
${doc}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${schema.rustName} {
${fields}
}`);
                    });

                    return implementations.join('');
                })()}

${models.messageSchemas.length === 0 && models.componentSchemas.length === 0 ? `
/// Example message structure when no messages are defined in the spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleMessage {
    pub id: String,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ExampleMessage {
    /// Create a new instance with required fields
    pub fn new(id: String, content: String, timestamp: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            id,
            content,
            timestamp,
        }
    }
}` : ''}
`}
        </File>
    );
}
