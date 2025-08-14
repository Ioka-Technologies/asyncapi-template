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

                        // Check if the message payload references a component schema
                        let payloadRustName = null;
                        let isComponentMessage = false;

                        if (schema.rawPayload && schema.rawPayload.$ref) {
                            const refName = schema.rawPayload.$ref.split('/').pop();
                            payloadRustName = toRustTypeName(refName);
                            isComponentMessage = true;
                        } else if (schema.payload && schema.payload.$ref) {
                            const refName = schema.payload.$ref.split('/').pop();
                            payloadRustName = toRustTypeName(refName);
                            isComponentMessage = true;
                        } else if (schema.payload && schema.payload['x-parser-schema-id']) {
                            // Handle resolved $ref references
                            const schemaId = schema.payload['x-parser-schema-id'];
                            if (models.schemaRegistry.has(schemaId)) {
                                payloadRustName = toRustTypeName(schemaId);
                                isComponentMessage = true;
                            }
                        }

                        // For component messages, always generate the message wrapper type
                        // even if the payload schema already exists
                        if (isComponentMessage && payloadRustName && !implementedTypes.has(schema.rustName)) {
                            implementedTypes.add(schema.rustName);
                            implementations.push(`
${doc}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${schema.rustName} {
    #[serde(flatten)]
    pub payload: ${payloadRustName},
}`);
                        } else if (!models.generatedTypes.has(schema.rustName) && !implementedTypes.has(schema.rustName)) {
                            // Generate both struct for inline message schemas
                            implementedTypes.add(schema.rustName);
                            implementations.push(`
${doc}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ${schema.rustName} {
${models.generateMessageStruct(schema.payload, schema.rustName)}
}`);
                        }
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
