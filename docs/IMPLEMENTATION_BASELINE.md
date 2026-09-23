# Implementation baseline

The version 0.1.0 implementation targets:

- C2PA Technical Specification 2.4
- `c2pa` Rust crate 0.90.20
- claim version 2
- C2PA Actions assertion version 2
- C2PA Ingredient assertion version 3 as selected by `c2pa-rs` for claim version 2
- ES256 claim signing
- C2PA claim-signing EKU `1.3.6.1.4.1.62558.2.1`
- Rust 1.88 minimum

`Cargo.lock` pins the dependency graph. The runtime links the official `c2pa-rs` implementation with `file_io` and `rust_native_crypto`. Default HTTP, remote-manifest fetching, and OpenSSL features are disabled.

## API choices

The tool creates a `c2pa::Context` for each operation with an empty network-host allow-list. It uses:

- `Builder` for manifest construction and embedding;
- `BuilderIntent::Update` for attesting an already signed, pixel-identical asset;
- `BuilderIntent::Edit` for unsigned attestation and real derivatives;
- ingredient ingestion through `Builder::add_ingredient_from_stream`;
- `Reader` for embedded-manifest validation; and
- the Rust-native ES256 signer created from a leaf certificate and a transient Keychain-supplied PKCS#8 key.

The application does not construct JUMBF, COSE, PNG C2PA chunks, JPEG application segments, or C2PA data hashes itself. Those operations remain in `c2pa-rs`. A read-only container auditor independently checks PNG framing and CRCs or JPEG APP11 sequencing and confirms that one embedded store is present. Semantic and cryptographic validation still uses the official library.

## Certificate profile

The local root and leaf use ECDSA P-256 with SHA-256. The root has `CA:TRUE`, path length zero, `keyCertSign`, and `cRLSign`, with an intended ten-year lifetime.

The leaf has `CA:FALSE`, `digitalSignature`, a 397-day lifetime, the dedicated C2PA claim-signing EKU, and `emailProtection` for compatibility with older validators. DNS and URI subject alternative names are included only when configured. `c2pa-rs` 0.90 expects an Organization attribute while reading a verified signing certificate, so the certificate repeats the required signer name as Organization when no separate organization was configured. Only the leaf is embedded in the C2PA `x5chain`; the root remains an external local trust anchor.

## Time and trust

Actions use the current system time. There is no hard-coded date or backdating option. Version 1 does not contact an RFC 3161 timestamp authority, so the claim time is not a trusted timestamp.

The default hierarchy is local. It is not represented as a certificate from the official C2PA trust ecosystem.

## Independent validation

The automated suite validates every generated output with a separate `Reader` pass. `c2patool` is an optional independent validator and is not a runtime dependency. The helper script is `scripts/validate-release.sh`.
