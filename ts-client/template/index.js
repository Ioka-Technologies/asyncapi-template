const { File } = require('@asyncapi/generator-react-sdk');
const React = require('react');

module.exports = function ({ asyncapi, params }) {
    // Extract info from AsyncAPI spec
    let title, version, description;
    try {
        const info = asyncapi.info();
        title = info.title();
        version = info.version();
        description = info.description();
    } catch (error) {
        title = 'UnknownAPI';
        version = '1.0.0';
        description = 'Generated API client';
    }

    // Helper function to check if a parameter contains unresolved template variables
    function isTemplateVariable(value) {
        return typeof value === 'string' && value.includes('{{') && value.includes('}}');
    }

    // Helper function to convert title to kebab-case
    function toKebabCase(str) {
        return str.toLowerCase().replace(/[^a-z0-9]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    }

    // Resolve parameters, falling back to extracted values if parameters contain template variables
    const clientName = (params.clientName && !isTemplateVariable(params.clientName))
        ? params.clientName
        : `${title.replace(/[^a-zA-Z0-9]/g, '')}Client`;

    const packageName = (params.packageName && !isTemplateVariable(params.packageName))
        ? params.packageName
        : `${toKebabCase(title)}-client`;

    const packageVersion = (params.packageVersion && !isTemplateVariable(params.packageVersion))
        ? params.packageVersion
        : version;

    const transports = (params.transports || 'websocket,http').split(',').map(t => t.trim());

    // Generate all files from the main index.js
    return [
        React.createElement(File, { name: "package.json" },
            JSON.stringify({
                name: packageName,
                version: packageVersion,
                description: `${description || title} - TypeScript AsyncAPI Client`,
                main: "dist/index.js",
                types: "dist/index.d.ts",
                scripts: {
                    build: "tsc",
                    dev: "tsc --watch",
                    test: "jest",
                    lint: "eslint src/**/*.ts",
                    prepare: "npm run build"
                },
                keywords: [
                    "asyncapi",
                    "websocket",
                    "http",
                    "client",
                    "typescript",
                    title.toLowerCase().replace(/[^a-z0-9]/g, '-')
                ],
                author: params.author || "AsyncAPI Generator",
                license: params.license || "Apache-2.0",
                dependencies: {
                    uuid: "^9.0.0"
                },
                optionalDependencies: {
                    ws: "^8.14.0"
                },
                devDependencies: {
                    "@types/ws": "^8.5.0",
                    "@types/uuid": "^9.0.0",
                    "@types/node": "^20.0.0",
                    typescript: "^5.0.0",
                    eslint: "^8.0.0",
                    "@typescript-eslint/eslint-plugin": "^6.0.0",
                    "@typescript-eslint/parser": "^6.0.0",
                    ...(params.generateTests && {
                        jest: "^29.0.0",
                        "@types/jest": "^29.0.0",
                        "ts-jest": "^29.0.0"
                    })
                },
                files: [
                    "dist/**/*",
                    "README.md",
                    "USAGE.md"
                ]
            }, null, 2)
        ),

        React.createElement(File, { name: "tsconfig.json" },
            JSON.stringify({
                compilerOptions: {
                    target: "ES2020",
                    module: "ES2020",
                    lib: ["ES2020", "DOM"],
                    outDir: "./dist",
                    rootDir: "./src",
                    strict: true,
                    esModuleInterop: true,
                    skipLibCheck: true,
                    forceConsistentCasingInFileNames: true,
                    declaration: true,
                    declarationMap: true,
                    sourceMap: true,
                    moduleResolution: "node",
                    allowSyntheticDefaultImports: true,
                    experimentalDecorators: true,
                    emitDecoratorMetadata: true,
                    resolveJsonModule: true,
                    typeRoots: ["node_modules/@types"]
                },
                include: [
                    "src/**/*"
                ],
                exclude: [
                    "node_modules",
                    "dist",
                    "**/*.test.ts",
                    "**/*.spec.ts"
                ]
            }, null, 2)
        ),

        React.createElement(File, { name: "README.md" },
            `# ${title}

${description || 'Generated TypeScript AsyncAPI client'}

## Installation

\`\`\`bash
npm install ${packageName}
\`\`\`

## Quick Start

See [USAGE.md](./USAGE.md) for detailed usage instructions.

## Generated from AsyncAPI

This client was generated from an AsyncAPI specification using the TypeScript AsyncAPI Client Generator.

- AsyncAPI Version: ${asyncapi.version()}
- Generated: ${new Date().toISOString()}
`
        ),

        React.createElement(File, { name: "USAGE.md" },
            `# ${title} - Usage Guide

This document shows how to use the generated TypeScript AsyncAPI client.

## Installation

### Browser Usage
For browser environments, install the package normally:
\`\`\`bash
npm install ${packageName}
\`\`\`

### Node.js Usage
For Node.js environments, you'll also need the WebSocket library:
\`\`\`bash
npm install ${packageName} ws
\`\`\`

## Environment Compatibility

This client automatically detects the environment and uses the appropriate WebSocket implementation:
- **Browser**: Uses the native \`WebSocket\` API
- **Node.js**: Uses the \`ws\` library (must be installed separately)

## WebSocket Usage

\`\`\`typescript
import { ${clientName} } from '${packageName}';

const client = new ${clientName}({
    type: 'websocket',
    url: 'ws://localhost:8080',
    headers: {
        'Authorization': 'Bearer your-token'
    }
});

// Connect to the WebSocket
await client.connect();

// Send a message and wait for response
try {
    const response = await client.sendMessage({
        text: 'Hello, World!',
        userId: '123'
    });
    console.log('Response:', response);
} catch (error) {
    console.error('Error:', error);
}

// Disconnect when done
await client.disconnect();
\`\`\`

## HTTP Usage

\`\`\`typescript
import { ${clientName} } from '${packageName}';

const client = new ${clientName}({
    type: 'http',
    url: 'http://localhost:8080/api',
    headers: {
        'Authorization': 'Bearer your-token'
    }
});

// Send HTTP request
try {
    const response = await client.sendMessage({
        text: 'Hello, World!',
        userId: '123'
    });
    console.log('Response:', response);
} catch (error) {
    console.error('Error:', error);
}
\`\`\`

## Configuration Options

\`\`\`typescript
interface TransportConfig {
    type: 'websocket' | 'http';
    url: string;
    headers?: Record<string, string>;
    timeout?: number;
}
\`\`\`

## Error Handling

The client throws specific error types:

- \`TransportError\`: General transport errors
- \`ConnectionError\`: Connection-related errors
- \`TimeoutError\`: Request timeout errors

\`\`\`typescript
import { TransportError, ConnectionError, TimeoutError } from '${packageName}';

try {
    await client.sendMessage(payload);
} catch (error) {
    if (error instanceof ConnectionError) {
        console.error('Connection failed:', error.message);
    } else if (error instanceof TimeoutError) {
        console.error('Request timed out:', error.message);
    } else if (error instanceof TransportError) {
        console.error('Transport error:', error.message);
    }
}
\`\`\`

## Troubleshooting

### WebSocket Issues in Node.js
If you get an error like "WebSocket implementation not available", make sure you have installed the \`ws\` package:
\`\`\`bash
npm install ws
\`\`\`

### Browser Compatibility
The client uses the native WebSocket API in browsers, which is supported in all modern browsers. No additional dependencies are required.
`
        )
    ];
};
