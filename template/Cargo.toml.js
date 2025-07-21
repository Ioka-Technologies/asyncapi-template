import { File } from '@asyncapi/generator-react-sdk';
import { kebabCase, oneLine } from '../helpers/index';
import { getRustDependencies } from '../helpers/rust-helpers';

export default function cargoTomlFile({ asyncapi, params }) {
    const server = asyncapi.allServers().get(params.server);
    const protocol = server.protocol();

    const packageName = params.packageName || kebabCase(asyncapi.info().title()) || 'asyncapi_client';
    const packageVersion = params.packageVersion || asyncapi.info().version() || '0.1.0';
    const packageDescription = params.packageDescription || oneLine(asyncapi.info().description()) || 'AsyncAPI generated Rust client';
    const packageAuthor = params.packageAuthor || 'AsyncAPI Generator';
    const edition = params.edition || '2021';
    const useAsyncStd = params.useAsyncStd || false;

    const dependencies = getRustDependencies(protocol, useAsyncStd);

    // Add optional dependencies based on schema formats
    const schemas = asyncapi.allSchemas();
    let needsChrono = false;
    let needsUuid = false;

    for (const [, schema] of schemas) {
        if (schema.format() === 'date-time' || schema.format() === 'date') {
            needsChrono = true;
        }
        if (schema.format() === 'uuid') {
            needsUuid = true;
        }
    }

    if (needsChrono) {
        dependencies['chrono'] = { version: '0.4', features: ['serde'] };
    }

    if (needsUuid) {
        dependencies['uuid'] = { version: '1.0', features: ['v4', 'serde'] };
    }

    const formatDependency = (name, dep) => {
        if (typeof dep === 'string') {
            return `${name} = "${dep}"`;
        } else {
            let result = `${name} = { version = "${dep.version}"`;
            if (dep.features && dep.features.length > 0) {
                result += `, features = [${dep.features.map(f => `"${f}"`).join(', ')}]`;
            }
            result += ' }';
            return result;
        }
    };

    const dependencyLines = Object.entries(dependencies)
        .map(([name, dep]) => formatDependency(name, dep))
        .join('\n');

    return (
        <File name="Cargo.toml">
            {`[package]
name = "${packageName}"
version = "${packageVersion}"
description = "${packageDescription}"
authors = ["${packageAuthor}"]
edition = "${edition}"
license = "MIT OR Apache-2.0"

[dependencies]
${dependencyLines}

[[bin]]
name = "main"
path = "src/main.rs"

[lib]
name = "${packageName.replace(/-/g, '_')}"
path = "src/lib.rs"
`}
        </File>
    );
}
