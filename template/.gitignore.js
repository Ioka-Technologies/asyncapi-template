import { File } from '@asyncapi/generator-react-sdk';

export default function gitignoreFile() {
    return (
        <File name=".gitignore">
            {`# Rust
/target/
**/*.rs.bk
Cargo.lock

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Logs
*.log

# Environment variables
.env
.env.local

# Configuration files with secrets
config.toml
secrets.toml

# Build artifacts
*.deb
*.rpm
*.tar.gz
*.zip

# Documentation build
/docs/_build/
`}
        </File>
    );
}
