

# Nyx - Lightweight Multi-Language Vulnerability Scanner

Nyx is a lightweight Rust CLI tool for scanning code across multiple programming languages to detect potential vulnerabilities and code quality issues. It works by converting source code to Abstract Syntax Trees (ASTs), analyzing control flow graphs, performing taint analysis, and searching for common vulnerability patterns.

## Features

- **Fast and Lightweight**: Written in Rust for optimal performance
- **Multi-Language Support**: Scans code in multiple programming languages
- **AST-Based Analysis**: Uses tree-sitter for accurate code parsing
- **Project Indexing**: Maintains an index to avoid rescanning unchanged files
- **Configurable**: Extensive configuration options for customizing scans
- **Multiple Output Formats**: Supports table, JSON, CSV, and SARIF output formats

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/nyx.git
cd nyx

# Build the project
cargo build --release

# Install the binary
cargo install --path .
```

## Usage

### Basic Scanning

```bash
# Scan the current directory
nyx scan

# Scan a specific directory
nyx scan /path/to/project

# Scan with specific output format
nyx scan --format json

# Scan only for high severity issues
nyx scan --high-only
```

### Managing Project Indexes

```bash
# Build or update index for current project
nyx index build

# Force rebuild index
nyx index build --force

# Show index status
nyx index status

# List all indexed projects
nyx list

# List all indexed projects with details
nyx list --verbose

# Remove a project from index
nyx clean project-name

# Clean all projects
nyx clean --all
```

## Supported Languages

Nyx currently supports scanning code in the following languages:

- Rust
- C
- C++
- Java
- Go
- PHP
- Python
- TypeScript
- JavaScript

## How It Works

1. **Code Traversal**: Nyx walks through your project's directory structure, respecting ignore files and exclusion patterns.

2. **AST Generation**: For each supported file, Nyx uses tree-sitter to parse the code into an Abstract Syntax Tree (AST).

3. **Pattern Matching**: Nyx applies language-specific vulnerability patterns to the AST to identify potential issues.

4. **Control Flow Analysis**: (Planned) Nyx will convert ASTs to control flow graphs for more sophisticated analysis.

5. **Taint Analysis**: (Planned) Nyx will track the flow of untrusted data through your application.

6. **Reporting**: Issues are reported with severity levels, file locations, and descriptions.

## Configuration

Nyx uses a configuration system with defaults that can be overridden by a user-specific configuration file. The configuration file is located at:

- Linux/macOS: `~/.config/nyx/nyx.local`
- Windows: `C:\Users\<username>\AppData\Roaming\ecpeter23\nyx\config\nyx.local`

Example configuration:

```toml
[scanner]
min_severity = "Medium"
follow_symlinks = true

[output]
default_format = "json"
color_output = true

[performance]
worker_threads = 8
```

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]
