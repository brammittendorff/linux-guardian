# Contributing

PRs welcome! See [DEVELOPMENT.md](DEVELOPMENT.md) for project structure and how to add detectors.

## Setup

```bash
git clone https://github.com/brammittendorff/linux-guardian.git
cd linux-guardian
cargo build
cargo test
```

## Workflow

1. Fork and create a feature branch
2. Make changes, add tests
3. Run `cargo fmt && cargo clippy -- -D warnings && cargo test`
4. Submit a PR referencing any related issue

## Commit messages

Follow conventional commits: `feat(scope): description`, `fix(scope): description`, etc.

## Guidelines

- Keep scans fast - use async I/O, parallelize where possible
- Minimize false positives - test on real systems
- No data collection or telemetry
- Add tests for new detectors

## License

By contributing, you agree your contributions are licensed under MIT.
