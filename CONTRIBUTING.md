# Contributing to Linux Guardian

Thank you for your interest in contributing to Linux Guardian! This document provides guidelines for contributing to the project.

## Ways to Contribute

- **Bug Reports**: Report issues you encounter
- **Feature Requests**: Suggest new security checks or improvements
- **Code Contributions**: Submit pull requests
- **Documentation**: Improve docs, guides, and examples
- **Testing**: Test on different Linux distributions

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Linux system (for testing)
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/brammittendorff/linux-guardian.git
cd linux-guardian

# Build and test
cargo build
cargo test
cargo build --release
```

## Development Workflow

### 1. Create an Issue

Before starting work, create an issue to discuss your proposed changes.

### 2. Fork and Branch

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/yourusername/linux-guardian.git
cd linux-guardian

# Create a feature branch
git checkout -b feature/your-feature-name
```

### 3. Make Changes

- Write clean, documented code
- Follow Rust conventions and idioms
- Add tests for new functionality
- Update documentation as needed

### 4. Test Thoroughly

```bash
# Run all tests
cargo test

# Test specific module
cargo test --lib detectors::ssh

# Build release version
cargo build --release

# Run on your system
sudo ./target/release/linux-guardian --mode comprehensive
```

### 5. Commit and Push

```bash
git add .
git commit -m "feat: add new security check for X"
git push origin feature/your-feature-name
```

### 6. Submit Pull Request

- Create a pull request from your fork
- Reference the related issue
- Describe what your changes do
- Include test results

## Code Style

### Rust Guidelines

- Use `rustfmt` for formatting
- Follow Clippy recommendations
- Write clear, self-documenting code
- Add comments for complex logic

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings
```

### Naming Conventions

- Functions: `snake_case`
- Types/Structs: `PascalCase`
- Constants: `SCREAMING_SNAKE_CASE`
- Modules: `snake_case`

### Documentation

- Add rustdoc comments for public APIs
- Include examples in docs
- Update README when adding features
- Keep CHANGELOG.md current

## Testing Requirements

### Unit Tests

All new code should include unit tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_your_feature() {
        // Test implementation
    }
}
```

### Integration Tests

For detector modules, add integration tests in `tests/`:

```rust
#[test]
fn test_detector_integration() {
    // Integration test
}
```

### Test Coverage

- Aim for >80% code coverage
- Test edge cases and error conditions
- Test with real-world data when possible

## Adding New Security Checks

### 1. Choose Category

Place your detector in the appropriate module:
- `src/detectors/privilege_escalation.rs` - Privilege escalation
- `src/detectors/cryptominer.rs` - Cryptominer detection
- `src/detectors/ssh.rs` - SSH security
- `src/detectors/network.rs` - Network analysis
- etc.

### 2. Implement Detector

```rust
pub async fn detect_your_threat() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Detection logic

    findings
}
```

### 3. Add CVE Knowledge

If detecting specific CVEs, add to `src/detectors/cve_knowledge_base.rs`:

```rust
CVEInfo {
    id: "CVE-2025-XXXXX",
    description: "Description of vulnerability",
    affected_versions: vec![VersionRange {
        min: "1.0.0".to_string(),
        max: "1.5.0".to_string(),
    }],
    severity: Severity::Critical,
    remediation: "Update to version X.X.X or later",
},
```

### 4. Update Documentation

- Add to README features list
- Document in relevant docs/ files
- Update CHANGELOG.md

## Commit Message Format

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `chore`: Maintenance

**Examples:**
```
feat(ssh): add SSH key age detection
fix(network): handle IPv6 connections correctly
docs(readme): update installation instructions
test(cryptominer): add tests for CPU usage detection
```

## Pull Request Guidelines

### PR Checklist

- [ ] Code follows project style
- [ ] All tests pass (`cargo test`)
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No compiler warnings
- [ ] Clippy passes without warnings

### PR Description Template

```markdown
## Description
Brief description of changes

## Related Issue
Closes #123

## Changes Made
- Change 1
- Change 2

## Testing
- Test 1 passed
- Test 2 passed

## Screenshots (if applicable)
```

## Security Considerations

When contributing security-related code:

- **Avoid False Positives**: Test thoroughly to minimize false alarms
- **Performance**: Keep scans fast and efficient
- **Privacy**: Don't collect or transmit user data
- **Documentation**: Clearly explain what is detected and why

## Adding CVE Detection

### Using CVE Database

```rust
use crate::cve_db::matcher::check_package_vulnerabilities;

// Check if package has known CVEs
let findings = check_package_vulnerabilities(
    "sudo",
    "1.9.15",
    &cve_db
).await;
```

### Manual CVE Checks

For critical CVEs, add hardcoded checks:

```rust
if package_name == "sudo" {
    if version_in_range(version, Some("1.9.14"), Some("1.9.17")) {
        findings.push(Finding {
            severity: Severity::Critical,
            category: "privilege_escalation".to_string(),
            title: "Vulnerable Sudo Version".to_string(),
            // ...
        });
    }
}
```

## Performance Guidelines

- Use async/await for I/O operations
- Parallelize independent checks
- Cache expensive operations
- Minimize filesystem access
- Use efficient data structures

## Questions?

- **Issues**: https://github.com/brammittendorff/linux-guardian/issues
- **Discussions**: https://github.com/brammittendorff/linux-guardian/discussions

## License

By contributing, you agree that your contributions will be licensed under the MIT OR Apache-2.0 license.

---

**Thank you for contributing to Linux Guardian!**
