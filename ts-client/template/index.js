import { File } from '@asyncapi/generator-react-sdk';
import React from 'react';

export default function ({ asyncapi, params }) {
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

    // Generate all files from the main index.js
    return [
        React.createElement(File, { name: 'package.json' },
            JSON.stringify({
                name: packageName,
                version: packageVersion,
                description: `${description || title} - TypeScript AsyncAPI Client`,
                main: 'dist/index.js',
                types: 'dist/index.d.ts',
                scripts: {
                    build: 'tsc',
                    dev: 'tsc --watch',
                    test: 'jest',
                    lint: 'eslint src/**/*.ts',
                    prepare: 'if [ ! -d \"node_modules\" ]; then npm install --include=dev; fi && npm run build'
                },
                keywords: [
                    'asyncapi',
                    'websocket',
                    'http',
                    'client',
                    'typescript',
                    title.toLowerCase().replace(/[^a-z0-9]/g, '-')
                ],
                author: params.author || 'AsyncAPI Generator',
                license: params.license || 'Apache-2.0',
                dependencies: {
                    uuid: '^9.0.0'
                },
                optionalDependencies: {
                    ws: '^8.14.0'
                },
                devDependencies: {
                    '@types/ws': '^8.5.0',
                    '@types/uuid': '^9.0.0',
                    '@types/node': '^20.0.0',
                    typescript: '^5.0.0',
                    eslint: '^8.0.0',
                    '@typescript-eslint/eslint-plugin': '^6.0.0',
                    '@typescript-eslint/parser': '^6.0.0',
                    ...(params.generateTests && {
                        jest: '^29.0.0',
                        '@types/jest': '^29.0.0',
                        'ts-jest': '^29.0.0'
                    })
                },
                files: [
                    'dist/**/*',
                    'README.md'
                ]
            }, null, 2)
        ),

        React.createElement(File, { name: 'tsconfig.json' },
            JSON.stringify({
                compilerOptions: {
                    target: 'ES2020',
                    module: 'ES2020',
                    lib: ['ES2020', 'DOM'],
                    outDir: './dist',
                    rootDir: './src',
                    strict: true,
                    esModuleInterop: true,
                    skipLibCheck: true,
                    forceConsistentCasingInFileNames: true,
                    declaration: true,
                    declarationMap: true,
                    sourceMap: true,
                    moduleResolution: 'node',
                    allowSyntheticDefaultImports: true,
                    experimentalDecorators: true,
                    emitDecoratorMetadata: true,
                    resolveJsonModule: true,
                    typeRoots: ['node_modules/@types']
                },
                include: [
                    'src/**/*'
                ],
                exclude: [
                    'node_modules',
                    'dist',
                    '**/*.test.ts',
                    '**/*.spec.ts'
                ]
            }, null, 2)
        ),

        React.createElement(File, { name: 'README.md' },
            `# ${title}

${description || 'Generated TypeScript AsyncAPI client'}

## Overview

This TypeScript client provides type-safe access to your AsyncAPI service with automatic transport selection and built-in error handling. Generated from your AsyncAPI specification, it offers seamless integration with both WebSocket and HTTP protocols.

## Technical Requirements

- Node.js 16+
- TypeScript 4.5+

## Supported Transports

- WebSocket (with auto-reconnection)
- HTTP (with retry logic)

## Installation

### For Node.js Projects

\`\`\`bash
npm install ${packageName} ws
\`\`\`

### For Browser Projects

\`\`\`bash
npm install ${packageName}
\`\`\`

## Quick Start

### WebSocket Client

\`\`\`typescript
import { ${clientName} } from '${packageName}';

const client = new ${clientName}({
    type: 'websocket',
    url: 'ws://localhost:8080',
    headers: {
        'Authorization': 'Bearer your-token'
    }
});

// Connect and send messages
await client.connect();
const response = await client.sendMessage({
    text: 'Hello, World!',
    userId: '123'
});
console.log('Response:', response);
\`\`\`

### HTTP Client

\`\`\`typescript
import { ${clientName} } from '${packageName}';

const client = new ${clientName}({
    type: 'http',
    url: 'http://localhost:8080/api',
    headers: {
        'Authorization': 'Bearer your-token'
    }
});

const response = await client.sendMessage({
    text: 'Hello, World!',
    userId: '123'
});
\`\`\`

## Configuration Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| \`type\` | \`'websocket' \\| 'http'\` | Transport protocol | Required |
| \`url\` | \`string\` | Server URL | Required |
| \`headers\` | \`Record<string, string>\` | Request headers | \`{}\` |
| \`timeout\` | \`number\` | Request timeout (ms) | \`30000\` |

## Error Handling

The client provides specific error types for different scenarios:

\`\`\`typescript
import { TransportError, ConnectionError, TimeoutError } from '${packageName}';

try {
    await client.sendMessage(payload);
} catch (error) {
    if (error instanceof ConnectionError) {
        console.error('Connection failed:', error.message);
    } else if (error instanceof TimeoutError) {
        console.error('Request timed out');
    } else if (error instanceof TransportError) {
        console.error('Transport error:', error.message);
    }
}
\`\`\`

## Environment Compatibility

- **Browser**: Uses native WebSocket API (no additional dependencies)
- **Node.js**: Requires \`ws\` package for WebSocket support

## Development

\`\`\`bash
# Build the project
npm run build

# Watch for changes
npm run dev

# Run tests
npm test

# Lint code
npm run lint
\`\`\`

## Generated from AsyncAPI

- **AsyncAPI Version**: ${asyncapi.version()}
- **Generated**: ${new Date().toISOString()}
- **Title**: ${title}
- **Version**: ${packageVersion}

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes and add tests
4. Run the test suite: \`npm test\`
5. Submit a pull request

## License

${params.license || 'Apache-2.0'}
`
        )
    ];
}
