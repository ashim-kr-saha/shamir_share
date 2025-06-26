# Contributing to shamir_share

We welcome contributions to the shamir_share library! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a new branch for your feature or bug fix
4. Make your changes
5. Test your changes thoroughly
6. Submit a pull request

## Development Requirements

- Rust 1.70 or later
- Cargo for building and testing

## Code Quality Standards

Before submitting a pull request, please ensure your code meets the following standards:

### Formatting and Linting

Run the following commands to ensure code quality:

```bash
# Format code
cargo fmt

# Run clippy for linting
cargo clippy -- -D warnings

# Run all tests
cargo test

# Run benchmarks (optional)
cargo bench
```

### Testing

- All new features must include comprehensive tests
- Existing tests must continue to pass
- Aim for high test coverage, especially for security-critical code
- Include both unit tests and integration tests where appropriate

### Documentation

- All public APIs must be documented with rustdoc comments
- Include examples in documentation where helpful
- Update the README.md if your changes affect the public API

### Security Considerations

This library handles sensitive cryptographic operations. Please ensure:

- No timing side-channels are introduced
- Constant-time operations are maintained where required
- Memory is handled securely (no sensitive data in debug output)
- Random number generation uses cryptographically secure sources

## Pull Request Process

1. Ensure your code follows the quality standards above
2. Update documentation as needed
3. Add tests for new functionality
4. Ensure all tests pass
5. Write a clear pull request description explaining:
   - What changes you made
   - Why you made them
   - How to test the changes

## Code of Conduct

Please be respectful and constructive in all interactions. We're committed to providing a welcoming environment for all contributors.

## Questions?

If you have questions about contributing, please open an issue on GitHub and we'll be happy to help!

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project (MIT License).