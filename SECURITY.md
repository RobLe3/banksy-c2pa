# Security policy

## Reporting a vulnerability

Please use GitHub's private security-advisory feature for vulnerabilities. Do not open a public issue containing private keys, Keychain exports, unpublished images, or other sensitive data.

This project is an early local tool. Security reports are reviewed on a best-effort basis; no response-time guarantee is offered.

## Private keys and user presence

`banksy-c2pa` stores the root and active leaf private keys as generic-password items in the user's local macOS login Keychain. It does not create private-key files.

Immediately before a secret is read, the CLI evaluates Apple's `DeviceOwnerAuthentication` policy. macOS chooses the mechanism. On a configured Mac this normally offers Touch ID and retains the login-password fallback. Cancelling or failing authentication stops the operation. A batch `sign` retrieves the leaf once after all deterministic preflight checks; a batch with nothing pending does not authenticate.

The authentication check and Keychain read are adjacent application steps, not one atomic biometric Keychain ACL. A normal Cargo-installed CLI lacks the provisioned access-group entitlement required for a Data Protection Keychain biometric ACL. A malicious process already running as the same unlocked user is outside this app-level boundary. FileVault, login security, Keychain locking, and host integrity remain important. See [Apple Technical Note TN3137](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains).

The keys are retrievable PKCS#8 values, not Secure Enclave key handles. The C2PA Rust signer needs the active leaf bytes briefly in process memory. Retrieval buffers are zeroized after use and are never intentionally printed or logged. Leaf rotation retrieves the root once.

## Files and output

Configuration and certificate directories use mode `0700`. The profile uses `0600`; public certificates use `0644`. Repository rules exclude common key and certificate-container formats. The root and leaf certificates are public verification material; the private root remains subject to macOS Keychain administration and backup behavior.

Source and parent paths cannot be destinations. Existing destinations require `--force`. A signed file is built beside the destination, synced, decoded, checked for a structurally valid embedded C2PA store, validated against the local root, checked for the requested actions and provenance relationship, and committed atomically. The committed file is reopened and checked again.

Directory scans do not follow symbolic links. Invalid provenance is reported instead of being extended automatically. Evidence ZIP auditing rejects unsafe paths, symbolic-link entries, duplicates, excessive entry counts or expanded sizes, checksum mismatches, changed credentials, and evidence metadata mismatches.

## Input and network boundaries

Image metadata is untrusted input handled by the image decoder and the official C2PA library. Version 1 supports detected PNG and JPEG files and does not invoke a shell.

The C2PA context has an empty network-host allow-list. Remote manifest fetching and default HTTP features are not compiled. RFC 3161 timestamping is disabled.

## Dependency audit policy

CI runs `cargo audit` against `Cargo.lock`. One transitive advisory is explicitly ignored:

- `RUSTSEC-2023-0071` affects the `rsa` crate through `c2pa`. The vulnerable operation concerns timing leakage in RSA private-key operations. This application creates and uses only local ES256 keys and does not perform RSA private-key signing. The exception is narrow, documented, and should be removed when the upstream dependency graph no longer requires it.

Unmaintained-package warnings, including the current transitive `proc-macro-error` warning, are tracked as dependency-maintenance signals rather than represented as exploitable vulnerabilities. Dependabot checks Cargo and GitHub Actions updates weekly.
