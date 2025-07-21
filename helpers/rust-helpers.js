import { snakeCase, pascalCase } from './general';

// Convert AsyncAPI type to Rust type
export function rustType(schema) {
    if (!schema) return 'String';

    const type = schema.type();

    switch (type) {
        case 'string':
            if (schema.format() === 'date-time') return 'chrono::DateTime<chrono::Utc>';
            if (schema.format() === 'date') return 'chrono::NaiveDate';
            if (schema.format() === 'uuid') return 'uuid::Uuid';
            return 'String';
        case 'integer':
            if (schema.format() === 'int64') return 'i64';
            if (schema.format() === 'int32') return 'i32';
            return 'i32';
        case 'number':
            if (schema.format() === 'double') return 'f64';
            if (schema.format() === 'float') return 'f32';
            return 'f64';
        case 'boolean':
            return 'bool';
        case 'array':
            const items = schema.items();
            return `Vec<${rustType(items)}>`;
        case 'object':
            return pascalCase(schema.uid() || 'Object');
        default:
            return 'String';
    }
}

// Convert field name to Rust field name (snake_case)
export function rustFieldName(name) {
    return snakeCase(name);
}

// Convert struct name to Rust struct name (PascalCase)
export function rustStructName(name) {
    return pascalCase(name);
}

// Convert module name to Rust module name (snake_case)
export function rustModuleName(name) {
    return snakeCase(name);
}

// Convert function name to Rust function name (snake_case)
export function rustFunctionName(name) {
    return snakeCase(name);
}

// Convert constant name to Rust constant name (SCREAMING_SNAKE_CASE)
export function rustConstantName(name) {
    return snakeCase(name).toUpperCase();
}

// Check if a type is optional
export function isOptional(schema, propertyName, required = []) {
    return !required.includes(propertyName);
}

// Get Rust dependencies based on protocol
export function getRustDependencies(protocol, useAsyncStd = false) {
    const baseDeps = {
        'serde': { version: '1.0', features: ['derive'] },
        'serde_json': '1.0',
        'anyhow': '1.0',
        'log': '0.4',
        'async-trait': '0.1',
    };

    if (useAsyncStd) {
        baseDeps['async-std'] = { version: '1.12', features: ['attributes'] };
    } else {
        baseDeps['tokio'] = { version: '1.0', features: ['full'] };
    }

    switch (protocol) {
        case 'mqtt':
        case 'mqtts':
            baseDeps['rumqttc'] = '0.24';
            break;
        case 'kafka':
        case 'kafka-secure':
            baseDeps['rdkafka'] = '0.36';
            break;
        case 'amqp':
        case 'amqps':
            baseDeps['lapin'] = '2.3';
            break;
        case 'ws':
        case 'wss':
            baseDeps['tokio-tungstenite'] = '0.21';
            break;
        case 'nats':
            baseDeps['async-nats'] = '0.33';
            break;
        case 'redis':
            baseDeps['redis'] = { version: '0.24', features: ['tokio-comp'] };
            break;
        case 'http':
        case 'https':
            baseDeps['reqwest'] = { version: '0.11', features: ['json'] };
            break;
    }

    return baseDeps;
}

// Generate Rust doc comment
export function rustDocComment(description, indent = '') {
    if (!description) return '';

    const lines = description.split('\n');
    return lines.map(line => `${indent}/// ${line}`).join('\n') + '\n';
}

// Check if schema has additional properties
export function hasAdditionalProperties(schema) {
    return schema.additionalProperties() !== false;
}

// Get enum values for Rust enum
export function getEnumValues(schema) {
    const enumValues = schema.enum();
    if (!enumValues || enumValues.length === 0) return [];

    return enumValues.map(value => {
        if (typeof value === 'string') {
            return pascalCase(value);
        }
        return value.toString();
    });
}

// Check if schema is an enum
export function isEnum(schema) {
    return schema.enum() && schema.enum().length > 0;
}

// Generate Rust attribute for serde
export function serdeAttribute(originalName, rustName) {
    if (originalName === rustName) return '';
    return `#[serde(rename = "${originalName}")]`;
}
