# Common Utilities

Shared utilities for AsyncAPI template generation, reducing code duplication across multiple templates.

## Overview

This folder provides shared utilities that are commonly used across different AsyncAPI templates (Rust client, Rust server, TypeScript client, etc.). It centralizes the logic for:

- String conversion and naming conventions
- Message processing and type extraction
- Channel handling and dynamic parameters
- Security analysis and authentication
- Template parameter resolution
- Operation processing and metadata extraction

## Usage

Import utilities using the `@common` path alias:

```javascript
// Import specific utilities
import { toRustIdentifier, getMessageTypeName } from '@common/string-utils';
import { getChannelAddress, isDynamicChannel } from '@common/channel-utils';

// Import from main index
import { toRustIdentifier, getMessageTypeName } from '@common';

// Import all utilities
import { getAllUtilities } from '@common';
const utils = getAllUtilities();
```

## Path Alias Setup

Each template should configure path aliases to resolve `@common` imports:

### For TypeScript Templates

Add to `tsconfig.json`:

```json
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@common/*": ["../common/src/*"],
      "@common": ["../common/src/index.js"]
    }
  }
}
```

### For JavaScript Templates

Add to `package.json`:

```json
{
  "imports": {
    "@common/*": "../common/src/*",
    "@common": "../common/src/index.js"
  }
}
```

Or configure your bundler/build tool to resolve the `@common` alias.

## Modules

### String Utils (`@common/string-utils`)

Provides consistent string conversion functions for different naming conventions:

- `toRustIdentifier(str)` - Converts to valid Rust identifier
- `toRustTypeName(str)` - Converts to PascalCase Rust type name
- `toRustFieldName(str)` - Converts to snake_case Rust field name
- `toPascalCase(str)` - Converts to PascalCase
- `toCamelCase(str)` - Converts to camelCase
- `toKebabCase(str)` - Converts to kebab-case
- `toSnakeCase(str)` - Converts to snake_case

### Message Utils (`@common/message-utils`)

Handles message processing and type extraction:

- `getMessageTypeName(message)` - Gets message type name
- `getMessageRustTypeName(message)` - Gets Rust type name for message
- `getPayloadRustTypeName(message)` - Gets payload type name
- `messageHasPayload(message)` - Checks if message has payload
- `getMessageContentType(message)` - Gets message content type

### Channel Utils (`@common/channel-utils`)

Manages channel addresses and dynamic parameters:

- `getChannelAddress(channel)` - Gets channel address
- `isDynamicChannel(address)` - Checks if channel has variables
- `extractChannelParameters(address)` - Extracts parameter info
- `generateChannelFormatting(address, params)` - Generates format strings
- `analyzeChannelServerMappings(asyncapi)` - Analyzes server restrictions

### Security Utils (`@common/security-utils`)

Analyzes security requirements and schemes:

- `operationHasSecurity(operation)` - Checks if operation requires auth
- `hasSecuritySchemes(asyncapi)` - Checks if spec has security schemes
- `getSecuritySchemeType(scheme)` - Gets security scheme type
- `extractOperationSecurityMap(asyncapi)` - Maps operations to security

### Template Utils (`@common/template-utils`)

Handles template parameters and common operations:

- `extractAsyncApiInfo(asyncapi)` - Extracts title, version, description
- `resolveTemplateParameters(params, info)` - Resolves template variables
- `generatePackageJson(params, info)` - Generates package.json content
- `validateTemplateParameters(params)` - Validates parameters

### Operation Utils (`@common/operation-utils`)

Processes AsyncAPI operations:

- `getOperationName(operation)` - Gets operation name/ID
- `getOperationAction(operation)` - Gets operation action (send/receive)
- `extractAllOperations(asyncapi)` - Extracts all operations with metadata
- `groupOperationsByAction(operations)` - Groups by send/receive
- `generateOperationHandlerName(operation)` - Generates handler names

## Common Patterns

### Processing Messages in Templates

```javascript
import { getMessageRustTypeName, getPayloadRustTypeName } from '@common/message-utils';

// In your template
const messages = channel.messages();
for (const message of messages) {
    const messageType = getMessageRustTypeName(message);
    const payloadType = getPayloadRustTypeName(message);

    // Generate code using these types
    console.log(`Message: ${messageType}, Payload: ${payloadType}`);
}
```

### Handling Dynamic Channels

```javascript
import {
    isDynamicChannel,
    extractChannelParameters,
    generateChannelFormatting
} from '@common/channel-utils';

const channelAddress = channel.address();
if (isDynamicChannel(channelAddress)) {
    const params = extractChannelParameters(channelAddress);
    const formatting = generateChannelFormatting(channelAddress, params);

    // Use formatting.formatString and formatting.formatArgs in templates
}
```

### Security Analysis

```javascript
import { operationHasSecurity, hasSecuritySchemes } from '@common/security-utils';

if (hasSecuritySchemes(asyncapi)) {
    const operations = asyncapi.operations();
    for (const operation of operations) {
        if (operationHasSecurity(operation)) {
            // Generate authentication code
        }
    }
}
```

## Benefits

1. **Consistency**: Ensures all templates use the same naming conventions and processing logic
2. **Maintainability**: Centralized utilities are easier to update and fix
3. **Reusability**: Common functionality doesn't need to be reimplemented
4. **Simplicity**: No separate package management, just shared folder imports
5. **Build Integration**: Easy to copy into dist folders during build

## Integration with Templates

### Build Process

Templates should copy the common utilities during their build process:

```javascript
// In template build script
import { copyFileSync, mkdirSync } from 'fs';
import { join } from 'path';

// Copy common utilities to output
const commonSrc = '../common/src';
const commonDest = './dist/common';

mkdirSync(commonDest, { recursive: true });
// Copy all files from common/src to dist/common
```

### Template Structure

```
template/
├── src/
│   ├── client.ts.js
│   └── models.ts.js
├── tsconfig.json        # Configure @common path alias
├── package.json         # Configure imports for @common
└── index.js            # Main template entry point

../common/
├── src/
│   ├── index.js
│   ├── string-utils.js
│   ├── message-utils.js
│   └── ...
└── README.md
```

## Contributing

When adding new utilities:

1. Add the function to the appropriate module (or create a new one)
2. Export it from the module
3. Add it to the main `src/index.js` exports
4. Update the `getAllUtilities()` function
5. Add appropriate JSDoc documentation
6. Update this README with usage examples

## Migration from Existing Templates

1. **Add path alias configuration** to template's tsconfig.json or package.json
2. **Replace helper imports** with `@common` imports
3. **Remove duplicated utility functions** from template helpers
4. **Update build process** to copy common utilities if needed
5. **Test template generation** to ensure output is identical

This approach provides all the benefits of shared utilities while maintaining simplicity and avoiding the complexity of separate package management.
