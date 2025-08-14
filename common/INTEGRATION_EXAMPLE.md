# Integration Example: Rust Client Template

This document shows how to integrate the common utilities with the rust-client template as an example.

## Current State (Before Integration)

The rust-client template currently has duplicated helper functions in:
- `rust-client/template/helpers/index.js`

## Integration Steps

### 1. Add Path Alias Configuration

Add to `rust-client/template/package.json`:

```json
{
  "name": "rust-client-template",
  "version": "1.0.0",
  "type": "module",
  "imports": {
    "@common/*": "../../../common/src/*",
    "@common": "../../../common/src/index.js"
  },
  "dependencies": {
    "@asyncapi/generator-react-sdk": "^1.0.20"
  }
}
```

### 2. Update Template Files

**Before (rust-client/template/src/client.rs.js):**
```javascript
import { File } from '@asyncapi/generator-react-sdk';
import { toRustIdentifier, getMessageTypeName } from '../helpers/index.js';

export default function({ asyncapi, params }) {
  // Template logic using helper functions
  const clientName = toRustIdentifier(params.clientName);
  // ...
}
```

**After (rust-client/template/src/client.rs.js):**
```javascript
import { File } from '@asyncapi/generator-react-sdk';
import { toRustIdentifier, getMessageTypeName } from '@common';

export default function({ asyncapi, params }) {
  // Template logic using common utilities
  const clientName = toRustIdentifier(params.clientName);
  // ...
}
```

### 3. Remove Duplicated Helper Functions

Delete or significantly reduce `rust-client/template/helpers/index.js`:

**Before (300+ lines):**
```javascript
// Lots of duplicated utility functions
function toRustIdentifier(str) {
  // 50+ lines of implementation
}

function getMessageTypeName(message) {
  // 30+ lines of implementation
}

// ... many more functions
```

**After (minimal or empty):**
```javascript
// This file can be removed entirely, or kept for template-specific helpers only
// All common utilities are now imported from @common
```

### 4. Update All Template Files

Update imports in all template files:

- `rust-client/template/src/auth.rs.js`
- `rust-client/template/src/client.rs.js`
- `rust-client/template/src/envelope.rs.js`
- `rust-client/template/src/errors.rs.js`
- `rust-client/template/src/lib.rs.js`
- `rust-client/template/src/models.rs.js`
- `rust-client/template/Cargo.toml.js`

**Example update for models.rs.js:**
```javascript
// Before
import { toRustTypeName, getMessageTypeName, getPayloadRustTypeName } from '../helpers/index.js';

// After
import { toRustTypeName, getMessageTypeName, getPayloadRustTypeName } from '@common';
```

### 5. Test the Integration

```bash
# Test template generation to ensure output is identical
cd rust-client
npm test

# Or test with a specific AsyncAPI file
asyncapi generate fromTemplate examples/simple/asyncapi.yaml ./template --output ./test-output-common
```

## Expected Benefits

### Code Reduction
- Remove ~300-400 lines from `rust-client/template/helpers/index.js`
- Cleaner, more focused template files
- Consistent utility behavior across all templates

### Maintenance
- Bug fixes in common utilities benefit all templates
- New utility functions available immediately
- Single source of truth for naming conventions

### Developer Experience
- Clear imports: `import { toRustIdentifier } from '@common'`
- IDE autocomplete works with path aliases
- Easy to find and understand utility functions

## Verification Checklist

After integration, verify:

- [ ] Template generates without errors
- [ ] Generated output is identical to before integration
- [ ] All imports resolve correctly
- [ ] No unused helper functions remain
- [ ] Path aliases work in development environment
- [ ] Build process works (if applicable)

## Rollback Plan

If issues arise:

1. Revert import changes in template files
2. Restore original `helpers/index.js` file
3. Remove path alias configuration
4. Test template generation

## Similar Integration for Other Templates

The same pattern applies to:

- **rust-server template**: More complex, more utilities used
- **ts-client template**: TypeScript-specific path alias configuration

Each template follows the same basic steps:
1. Add path alias configuration
2. Update imports to use `@common`
3. Remove duplicated helper functions
4. Test and verify

This approach provides immediate benefits while maintaining the ability to rollback if needed.
