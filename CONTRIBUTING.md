# Contributing to AsyncAPI Rust Template

Thank you for your interest in contributing to the AsyncAPI Rust Template! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Template Development](#template-development)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Code of Conduct

This project follows the [AsyncAPI Code of Conduct](https://github.com/asyncapi/.github/blob/master/CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Node.js 16+ and npm
- Rust 1.70+
- AsyncAPI CLI: `npm install -g @asyncapi/cli`
- Git

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/rust-template.git
   cd rust-template
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Verify Setup**
   ```bash
   npm test
   npm run test:generate
   ```

## Contributing Guidelines

### Types of Contributions

We welcome several types of contributions:

- 🐛 **Bug Reports**: Report issues with template generation
- 🚀 **Feature Requests**: Suggest new features or improvements
- 📝 **Documentation**: Improve documentation and examples
- 🔧 **Code Contributions**: Fix bugs or implement features
- 🧪 **Testing**: Add or improve tests
- 📦 **Protocol Support**: Add support for new protocols

### Before Contributing

1. **Check Existing Issues**: Look for existing issues or discussions
2. **Create an Issue**: For significant changes, create an issue first
3. **Discuss**: Engage with maintainers and community for feedback

## Template Development

### Template Structure

```
template/
├── src/                    # Rust source templates
│   ├── main.rs.js         # Main application template
│   ├── config.rs.js       # Configuration template
│   ├── server.rs.js       # Server implementation template
│   ├── handlers.rs.js     # Message handlers template
│   ├── models.rs.js       # Message models template
│   └── middleware.rs.js   # Middleware template
├── Cargo.toml.js          # Cargo manifest template
├── README.md.js           # Project README template
└── helpers/               # Template helper functions
    ├── rust-helpers.js    # Rust-specific helpers
    └── general.js         # General utilities
```

### Template Development Guidelines

#### 1. Template Files

Template files use the `.js` extension and export React components:

```javascript
import { File } from '@asyncapi/generator-react-sdk';

export default function MyTemplate({ asyncapi, params }) {
    // Template logic here
    return (
        <File name="output.rs">
            {`// Generated Rust code here`}
        </File>
    );
}
```

#### 2. Helper Functions

Keep helper functions in the `helpers/` directory:

```javascript
// helpers/rust-helpers.js
function toRustIdentifier(str) {
    // Convert string to valid Rust identifier
    return str.replace(/[^a-zA-Z0-9_]/g, '_');
}

module.exports = {
    toRustIdentifier,
    // ... other helpers
};
```

#### 3. AsyncAPI Data Access

Use the AsyncAPI parser methods to access specification data:

```javascript
export default function MyTemplate({ asyncapi, params }) {
    const info = asyncapi.info();
    const title = info.title();
    const servers = asyncapi.servers();
    const channels = asyncapi.channels();

    // Process data and generate code
}
```

#### 4. Error Handling

Always handle potential errors gracefully:

```javascript
export default function MyTemplate({ asyncapi, params }) {
    try {
        const servers = asyncapi.servers();
        if (!servers) {
            // Handle missing servers
            return <File name="empty.rs">{`// No servers defined`}</File>;
        }

        // Process servers
    } catch (error) {
        console.warn('Error processing servers:', error);
        // Provide fallback
    }
}
```

### Adding Protocol Support

To add support for a new protocol:

1. **Update Cargo.toml Template**
   ```javascript
   // template/Cargo.toml.js
   if (protocols.has('your-protocol')) {
       protocolDeps += 'your-protocol-crate = "1.0"\n';
   }
   ```

2. **Add Server Handler**
   ```javascript
   // template/src/server.rs.js
   ${Array.from(protocols).map(protocol => `
   pub async fn start_${protocol}_handler(&self) -> Result<()> {
       // Protocol-specific implementation
   }`).join('\n')}
   ```

3. **Update Documentation**
   - Add protocol to README.md
   - Update USAGE.md with examples
   - Add test fixtures

4. **Add Tests**
   ```javascript
   // test/fixtures/your-protocol.yaml
   asyncapi: 2.6.0
   servers:
     your-protocol:
       url: your-protocol://localhost:1234
       protocol: your-protocol
   ```

## Testing

### Test Structure

```
test/
├── fixtures/              # AsyncAPI test specifications
│   ├── simple.yaml       # Basic test case
│   ├── mqtt.yaml         # MQTT protocol test
│   └── multi-protocol.yaml
├── output/               # Generated test output
└── integration/          # Integration tests
```

### Running Tests

```bash
# Run all tests
npm test

# Test template generation
npm run test:generate

# Test specific fixture
npm run test:generate:simple
npm run test:generate:mqtt

# Validate generated code compiles
npm run test:compile
```

### Adding Tests

1. **Create Test Fixture**
   ```yaml
   # test/fixtures/new-feature.yaml
   asyncapi: 2.6.0
   info:
     title: New Feature Test
     version: 1.0.0
   # ... rest of spec
   ```

2. **Add Test Script**
   ```json
   // package.json
   {
     "scripts": {
       "test:generate:new-feature": "asyncapi generate fromTemplate test/fixtures/new-feature.yaml . --output test/output/new-feature --force-write"
     }
   }
   ```

3. **Verify Compilation**
   ```bash
   cd test/output/new-feature
   cargo check
   ```

### Test Guidelines

- **Comprehensive Coverage**: Test all supported protocols and features
- **Edge Cases**: Test with minimal and complex specifications
- **Error Handling**: Test invalid specifications
- **Compilation**: Ensure generated code compiles
- **Functionality**: Test that generated servers can start

## Documentation

### Documentation Standards

- **Clear Examples**: Provide working code examples
- **Complete Coverage**: Document all features and options
- **User-Focused**: Write from the user's perspective
- **Up-to-Date**: Keep documentation synchronized with code

### Documentation Files

- `README.md`: Overview and quick start
- `USAGE.md`: Comprehensive usage guide
- `CONTRIBUTING.md`: This file
- Template comments: Inline documentation in templates

### Writing Guidelines

1. **Use Clear Language**: Avoid jargon, explain technical terms
2. **Provide Examples**: Show don't just tell
3. **Structure Content**: Use headings, lists, and tables
4. **Test Examples**: Ensure all code examples work
5. **Link Related Content**: Cross-reference related sections

## Pull Request Process

### Before Submitting

1. **Test Your Changes**
   ```bash
   npm test
   npm run test:generate
   npm run lint
   ```

2. **Update Documentation**
   - Update relevant documentation files
   - Add examples for new features
   - Update CHANGELOG.md

3. **Follow Coding Standards**
   - Use consistent formatting
   - Add comments for complex logic
   - Follow existing patterns

### PR Guidelines

1. **Clear Title**: Describe what the PR does
2. **Detailed Description**: Explain the changes and why
3. **Link Issues**: Reference related issues
4. **Small Changes**: Keep PRs focused and manageable
5. **Tests**: Include tests for new functionality

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Breaking change

## Testing
- [ ] Tests pass locally
- [ ] Generated code compiles
- [ ] Documentation updated

## Checklist
- [ ] Code follows project standards
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

### Review Process

1. **Automated Checks**: CI/CD runs tests and linting
2. **Maintainer Review**: Core maintainers review changes
3. **Community Feedback**: Community members may provide input
4. **Approval**: At least one maintainer approval required
5. **Merge**: Maintainer merges after approval

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Steps

1. **Update Version**
   ```bash
   npm version patch|minor|major
   ```

2. **Update CHANGELOG.md**
   - Add release notes
   - List all changes
   - Credit contributors

3. **Create Release**
   - Tag the release
   - Create GitHub release
   - Publish to npm (if applicable)

4. **Announce**
   - AsyncAPI Slack
   - Community forums
   - Social media

## Development Tips

### Debugging Templates

1. **Use Console Logging**
   ```javascript
   console.log('Debug info:', JSON.stringify(data, null, 2));
   ```

2. **Test Incrementally**
   - Make small changes
   - Test frequently
   - Use simple test cases

3. **Check Generated Output**
   - Review generated files
   - Verify syntax highlighting
   - Test compilation

### Common Patterns

1. **Safe Property Access**
   ```javascript
   const title = info.title && info.title() || 'Default Title';
   ```

2. **Conditional Generation**
   ```javascript
   {protocols.has('mqtt') && `
   // MQTT-specific code
   `}
   ```

3. **Helper Functions**
   ```javascript
   function generateStruct(schema) {
       if (!schema) return '';
       // Generate struct code
   }
   ```

## Getting Help

### Resources

- 📖 [AsyncAPI Documentation](https://www.asyncapi.com/docs)
- 💬 [AsyncAPI Slack](https://asyncapi.com/slack-invite)
- 🐛 [Issue Tracker](https://github.com/asyncapi/rust-template/issues)
- 📧 [Mailing List](https://groups.google.com/forum/#!forum/asyncapi-users)

### Asking Questions

When asking for help:

1. **Search First**: Check existing issues and documentation
2. **Provide Context**: Include relevant code and error messages
3. **Minimal Example**: Create a minimal reproduction case
4. **Environment Info**: Include versions and system information

### Mentorship

New contributors are welcome! Maintainers are happy to:

- Review your first PR
- Provide guidance on best practices
- Help with technical questions
- Suggest good first issues

## Recognition

Contributors are recognized in:

- CHANGELOG.md for each release
- GitHub contributors list
- AsyncAPI community highlights
- Conference talks and blog posts

Thank you for contributing to the AsyncAPI Rust Template! 🦀✨
