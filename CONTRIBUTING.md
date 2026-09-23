# Contributing

Issues and focused pull requests are welcome. Please keep claims about provenance, identity, and trust precise: cryptographic validity, local trust, and public C2PA trust are different properties.

## Development setup

Requirements are Rust 1.88 or newer and, for Keychain integration tests, macOS. Most parsing and policy tests also run on Linux.

```bash
git clone https://github.com/RobLe3/banksy-c2pa.git
cd banksy-c2pa
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo package --locked --allow-dirty
```

Do not commit private images, certificates, private keys, Keychain exports, profiles containing personal data, evidence archives, databases, or built binaries. Use generated test fixtures and fictional identities such as `example.test`.

## Pull requests

- Add or update tests for behavior changes.
- Preserve the distinction between `attest` and `derivative`.
- Keep network access disabled unless a reviewed design explicitly changes the threat model.
- Update user-facing documentation when flags, reports, or trust semantics change.
- Run formatting, Clippy, tests, package inspection, Gitleaks, and `cargo audit` before requesting review.

Security vulnerabilities should be reported privately as described in [SECURITY.md](SECURITY.md), not through a public issue.
