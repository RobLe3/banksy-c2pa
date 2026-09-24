# banksy-c2pa

`banksy-c2pa` is a local macOS CLI for preserving and extending C2PA image provenance. It can add a narrowly scoped editorial or publication claim to an existing PNG or JPEG, retain an upstream Content Credential when one is present, and link a genuine edited result to its parent.

It does **not** detect whether an arbitrary image was made with AI. It does not make a local certificate publicly trusted, prove authorship or copyright, recover metadata that was already removed, or establish that an image is authentic in every sense.

## Why the name?

The name began as a joke about treating a self-issued signature as if it could turn an AI-generated image into something “hand-drawn by Banksy.” It cannot. The tool makes the opposite point: provenance claims should be narrow, inspectable, and honest. It preserves an upstream OpenAI credential where one exists and records the local editorial action separately. The project is independent and is not affiliated with or endorsed by the artist Banksy.

## What it does

- **Attest an unchanged image.** `attest` verifies that decoded pixels are unchanged and records a metadata/editorial action. If the input already has valid C2PA provenance, the new claim is an update in the same history.
- **Sign a derivative.** `derivative` requires an edited input whose pixels differ from a named parent. The parent and any valid embedded history remain reachable as a C2PA ingredient.
- **Find work automatically.** `status` and `sign` distinguish unsigned images, externally signed images, locally signed outputs, originals already covered by a signed sibling, invalid files, and unreadable files.
- **Protect the local key.** Private keys live in the macOS login Keychain. LocalAuthentication asks for user presence immediately before retrieval, offering Touch ID when macOS makes it available and retaining the system password fallback.
- **Validate before commit.** The tool checks the embedded PNG `caBX` or JPEG JUMBF store, C2PA signature, local chain, expected actions, provenance relationship, pixels, and final file hash.
- **Package exact bytes.** `package` creates a byte-preserving evidence ZIP for transfer paths that might otherwise re-encode an uploaded image.

The generated certificate hierarchy is local and private by default. A valid result against that root is not the same as public C2PA trust. See [TRUST_MODEL.md](TRUST_MODEL.md).

## Requirements

- macOS; Apple Silicon is the primary tested platform
- Xcode Command Line Tools
- Rust 1.88 or newer
- Touch ID configured in macOS if biometric authentication is desired

## Platform support

The current release is designed and tested for macOS. Private signing keys are stored in the macOS login Keychain, and macOS LocalAuthentication provides Touch ID or password-based user presence. Windows support is not currently included. If you need Windows support, fork this repository and adapt the key-storage and authentication backend for Windows while preserving the security boundaries documented in [SECURITY.md](SECURITY.md).

The current release is source-first. No unsigned prebuilt executable is published.

## Install

Install the tagged source with Cargo:

```bash
cargo install --locked --git https://github.com/RobLe3/banksy-c2pa --tag v0.1.0
```

Or build a checkout:

```bash
git clone https://github.com/RobLe3/banksy-c2pa.git
cd banksy-c2pa
cargo build --release
install -d "$HOME/.local/bin"
install -m 0755 target/release/banksy-c2pa "$HOME/.local/bin/banksy-c2pa"
```

Ensure Cargo's bin directory or `$HOME/.local/bin` is on `PATH`.

## First run

Run the tool with no arguments:

```bash
banksy-c2pa
```

The menu offers to create a local identity when signing is first requested. Setup asks for a signer name. Organization, domain, identity URI, and manifest vendor are optional. These values become public certificate or manifest metadata; they are not independently verified and do not establish public trust.

You can also initialize directly:

```bash
banksy-c2pa init --name "Example Studio image signer" \
  --organization "Example Studio" \
  --domain example.com \
  --uri https://example.com/provenance \
  --vendor example.com
```

In an interactive terminal, omitted fields are prompted for. For non-interactive use and `--json`, `--name` is required when creating a new profile. Running `init` again is idempotent. Existing profiles, including profiles created by earlier versions with a `service_name` field, keep their identity and certificates. Identity options are rejected for an existing profile so an established identity cannot be rewritten accidentally.

The public profile and certificates are created under `~/.config/banksy-c2pa`. Private PKCS#8 keys are stored in the macOS login Keychain, not in that directory. Rotate only the leaf certificate with:

```bash
banksy-c2pa init --rotate-signer
```

## Everyday use

Open the menu in a folder of images:

```bash
cd ./illustrations
banksy-c2pa
```

Or use the short command workflow:

```bash
banksy-c2pa status .
banksy-c2pa sign .
```

`sign` defaults to the current directory. It signs every pending PNG or JPEG, creates `NAME.banksy-signed.EXT` beside the source, and uses one authentication prompt for the batch. Running it again safely skips local outputs and originals already covered by a valid, pixel-identical signed sibling.

Scans are non-recursive unless requested:

```bash
banksy-c2pa status ./incoming --recursive --check --json
banksy-c2pa sign ./incoming --recursive --published
```

Status meanings:

| State | Meaning |
| --- | --- |
| `unsigned` | No C2PA manifest was found; the image is pending. |
| `signed-external` | Valid C2PA provenance exists, but not from the configured local root; the image is pending. |
| `signed-local` | The active manifest validates against the configured local root. |
| `covered` | A valid local `.banksy-signed` sibling has identical decoded pixels. |
| `invalid` | Provenance or managed-output checks failed; automatic signing stops. |
| `unreadable` | The image could not be inspected. |

A `.banksy-signed` filename is not proof of a signature. Such a file must contain and validate an embedded credential or it is reported as invalid.

## OpenAI-generated images

Supported images generated by ChatGPT, Codex, and the OpenAI API may include C2PA metadata and a SynthID watermark. Coverage varies by product, model, export path, format, and creation date. `banksy-c2pa` works with the **C2PA** part only:

```bash
banksy-c2pa inspect openai-image.png
banksy-c2pa attest openai-image.png --published
banksy-c2pa verify openai-image.banksy-signed.png --trust-local-root
```

When the input has a valid OpenAI C2PA manifest, `attest` adds a separate local update while keeping the upstream manifest reachable. For a real edit, use `derivative --parent ... --input ...`; do not describe changed pixels as an unchanged attestation.

The tool does not inspect or certify SynthID. It is not designed to remove, evade, or replace OpenAI provenance. A missing C2PA manifest does not prove that an image is human-made, and provenance stripped before input cannot be reconstructed. Read [OpenAI provenance workflows and limits](docs/OPENAI_PROVENANCE.md) for details and source links.

## Explicit signing commands

Attest an image without claiming a visible edit:

```bash
banksy-c2pa attest image.png --published \
  --description "Prepared for publication; pixels unchanged"
```

Sign a real edited result and identify its parent:

```bash
banksy-c2pa derivative \
  --parent original.png \
  --input edited.png \
  --description "Cropped and annotated for publication" \
  --published
```

Neither command overwrites an input. Existing destinations require `--force`. Signing occurs beside the destination and the validated temporary file is committed only after all checks pass.

## Inspect, verify, audit, and transfer

```bash
banksy-c2pa inspect image.banksy-signed.png
banksy-c2pa verify image.banksy-signed.png
banksy-c2pa verify image.banksy-signed.png --trust-local-root
banksy-c2pa audit image.banksy-signed.png
banksy-c2pa package image.banksy-signed.png -o delivery.zip
banksy-c2pa audit delivery.zip
```

`inspect`, `verify`, and `identity` use public material and do not retrieve a private key. `--trust-local-root` means “validate against my configured private root,” not “treat this identity as publicly trusted.” Use global `--json` for structured output. Optional identity fields appear as `null` when they were not configured.

Some upload services decode and re-encode images, removing container metadata even when visible pixels look unchanged. Send the evidence ZIP as an opaque file or document when exact preservation matters, then compare its hash and audit it after download. See [docs/TRANSFER_INTEGRITY.md](docs/TRANSFER_INTEGRITY.md).

Exit codes are `0` for success, `1` for runtime/configuration failure, `2` for command-line usage errors, and `3` for invalid provenance or a failed policy check.

## Security and trust boundaries

The Keychain secret is retrievable: the C2PA signer needs the PKCS#8 bytes briefly in memory. The buffer is zeroized after use and is not logged. The LocalAuthentication check and Keychain read are adjacent application steps, not a Secure Enclave key operation or an atomic biometric Keychain ACL. See [SECURITY.md](SECURITY.md) for the precise boundary.

A C2PA signature establishes that a key holder signed particular assertions bound to particular bytes. It does not by itself prove authorship, copyright ownership, accuracy, domain control, legal identity, or affiliation. A local root can be useful in a controlled workflow without being on a public trust list.

## Documentation

- [OpenAI provenance workflows and limits](docs/OPENAI_PROVENANCE.md)
- [C2PA manifest profile](docs/C2PA_PROFILE.md)
- [Trust model](TRUST_MODEL.md)
- [Security model and dependency policy](SECURITY.md)
- [Transfer integrity](docs/TRANSFER_INTEGRITY.md)
- [Implementation baseline](docs/IMPLEMENTATION_BASELINE.md)
- [Sample validation transcript](docs/VALIDATION_TRANSCRIPT.md)
- [Contributing](CONTRIBUTING.md)

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo package --locked --allow-dirty
```

For an optional independent file check, install `c2patool` and run `scripts/validate-release.sh IMAGE...`. See the upstream [c2patool signing documentation](https://github.com/contentauth/c2patool/blob/main/docs/signing.md).

## License

MIT. See [LICENSE](LICENSE).
