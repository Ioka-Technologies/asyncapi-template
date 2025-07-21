# Contributing to AsyncAPI Rust Template

Thank you for your interest in contributing to the AsyncAPI Rust Template! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

We welcome contributions of all kinds:

- 🐛 **Bug Reports**: Help us identify and fix issues
- ✨ **Feature Requests**: Suggest new features or improvements
- 📝 **Documentation**: Improve our docs and examples
- 🔧 **Code Contributions**: Submit bug fixes and new features
- 🧪 **Testing**: Help improve our test coverage
- 💡 **Ideas**: Share your thoughts on the project direction

## 🚀 Getting Started

### Prerequisites

- **Node.js** >= 18.0.0
- **npm** >= 8.0.0
- **Git**
- **Rust** (for testing generated code)

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/rust-template.git
   cd rust-template
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Run Tests**
   ```bash
   npm test
   ```

4. **Test Code Generation**
   ```bash
   npm run test:generate
   ```

### Project Structure

```
rust-template/
├── template/                 # Template files (React components)
│   ├── src/                 # Generated Rust source files
│   ├── examples/            # Generated example files
│   ├── Cargo.toml.js        # Cargo.toml template
│   ├── README.md.js         # Generated README template
│   └── index.js             # Main template entry point
├── helpers/                 # Helper functions
│   ├── index.js            # General helpers
│   └── rust-helpers.js     # Rust-specific helpers
├── test/                   # Test files
│   ├── fixtures/           # Test AsyncAPI specifications
│   └── output/             # Generated test output
├── docs/                   # Documentation
├── package.json            # Package configuration
└── README.md               # Main documentation
```

## 🔧 Development Workflow

### Making Changes

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   npm test                    # Run unit tests
   npm run test:generate       # Test code generation
   npm run lint               # Check code style
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

   We follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation changes
   - `test:` for test additions/changes
   - `refactor:` for code refactoring
   - `chore:` for maintenance tasks

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

### Testing Generated Code

To test the generated Rust code:

1. **Generate Test Output**
   ```bash
   npm run test:generate:mqtt
   ```

2. **Test the Generated Code**
   ```bash
   cd test/output/mqtt
   cargo check                 # Check compilation
   cargo test                  # Run tests
   cargo clippy               # Run linter
   ```

## 📝 Code Style Guidelines

### JavaScript/React

- Use **ES6+** features
- Follow **Prettier** formatting (run `npm run format`)
- Use **ESLint** rules (run `npm run lint`)
- Write **JSDoc** comments for functions
- Use **descriptive variable names**

### Generated Rust Code

- Follow **Rust naming conventions**
- Use **snake_case** for functions and variables
- Use **PascalCase** for types and structs
- Include **comprehensive documentation**
- Follow **Rust API Guidelines**

### Template Files

- Use **React functional components**
- Keep **logic minimal** in templates
- Extract **complex logic** to helpers
- Use **template literals** for code generation
- Include **proper indentation** in generated code

## 🧪 Testing

### Unit Tests

```bash
npm test                    # Run all tests
npm run test:watch         # Run tests in watch mode
npm run test:coverage      # Generate coverage report
```

### Integration Tests

```bash
npm run test:generate      # Test code generation
```

### Manual Testing

1. Create a test AsyncAPI specification
2. Generate code using the template
3. Verify the generated code compiles and runs
4. Test with different protocols and configurations

## 📚 Documentation

### Adding Documentation

- Update relevant **README** sections
- Add **JSDoc** comments to functions
- Include **examples** for new features
- Update **parameter descriptions** in package.json

### Documentation Standards

- Use **clear, concise language**
- Include **code examples**
- Provide **step-by-step instructions**
- Link to **relevant resources**

## 🐛 Reporting Issues

### Bug Reports

When reporting bugs, please include:

1. **AsyncAPI specification** that reproduces the issue
2. **Generator parameters** used
3. **Expected behavior**
4. **Actual behavior**
5. **Error messages** (if any)
6. **Environment details** (Node.js version, OS, etc.)

### Feature Requests

When requesting features, please include:

1. **Use case description**
2. **Proposed solution**
3. **Alternative solutions** considered
4. **Additional context**

## 🔄 Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `package.json`
2. Update `CHANGELOG.md`
3. Run full test suite
4. Create release PR
5. Tag release after merge
6. Publish to npm

## 🏆 Recognition

Contributors are recognized in:

- **README.md** contributors section
- **Release notes**
- **GitHub contributors** page

## 📞 Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and ideas
- **AsyncAPI Slack**: Join the community chat
- **Stack Overflow**: Tag questions with `asyncapi`

## 🎯 Areas for Contribution

### High Priority

- **Protocol Support**: Add support for new protocols
- **Middleware**: Implement additional middleware types
- **Testing**: Improve test coverage and add integration tests
- **Documentation**: Enhance examples and guides
- **Performance**: Optimize generated code performance

### Good First Issues

- **Documentation improvements**
- **Example additions**
- **Test case additions**
- **Helper function improvements**
- **Error message enhancements**

### Advanced Contributions

- **New transport implementations**
- **Advanced middleware features**
- **Performance optimizations**
- **Complex protocol support**
- **Integration with external tools**

## 📋 Contribution Checklist

Before submitting a PR, ensure:

- [ ] Code follows style guidelines
- [ ] Tests pass (`npm test`)
- [ ] Generated code compiles (`cargo check`)
- [ ] Documentation is updated
- [ ] Commit messages follow conventions
- [ ] PR description is clear and detailed
- [ ] Breaking changes are documented

## 🤔 Questions?

If you have questions about contributing:

1. Check existing **GitHub Issues** and **Discussions**
2. Join the **AsyncAPI Slack** community
3. Create a **new Discussion** for general questions
4. Create an **Issue** for specific problems

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to the AsyncAPI Rust Template! Your efforts help make async messaging in Rust more accessible and powerful for everyone. 🚀
