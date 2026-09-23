# Sample validation transcript

This abbreviated transcript shows the expected shape of a local run. Names, hashes, fingerprints, dates, and paths vary. It does not represent public C2PA trust.

```console
$ banksy-c2pa init --name "Example Studio image signer"
Local identity ready

Profile
  /Users/operator/.config/banksy-c2pa/profile.toml

Signer SHA-256
  <SHA-256 fingerprint>

Private keys
  macOS login Keychain (local; no private key files)

Authentication
  macOS user authentication immediately before retrieval; Touch ID is offered when available, with login-password fallback

Trust
  private/local

Public C2PA trust
  not established (a local root is not a public trust credential)

$ banksy-c2pa status .
STATUS                             FILE
Foreign signed — needs local signature image.png
1 images: 1 need signing (0 unsigned, 1 foreign signed), 0 local signed, 0 covered, 0 invalid, 0 unreadable

$ banksy-c2pa sign .
signed   signed-external    ./image.png
  output: ./image.banksy-signed.png

Summary: 1 scanned, 1 signed, 0 skipped, 0 failed; 1 authentication prompt

$ banksy-c2pa verify image.banksy-signed.png --trust-local-root
C2PA manifest
  yes

Claim signature and asset binding
  valid

Certificate chain
  cryptographically valid

Local trust
  valid against the configured private root

Public C2PA trust
  not claimed or established

Trusted RFC 3161 timestamp
  no

$ banksy-c2pa audit image.banksy-signed.png
valid-local         image.banksy-signed.png
  SHA-256: <complete file SHA-256>
  embedded: yes (PNG caBX; <bytes> bytes)
  signature: valid; local trust: yes; manifests: 2; upstream preserved: yes

Summary: 1 target, 1 passed, 0 failed

$ banksy-c2pa package image.banksy-signed.png -o delivery.zip
Evidence bundle created

Output
  delivery.zip

Archive verification
  passed
```

An optional independent check is:

```console
$ c2patool image.banksy-signed.png --info
Information for image.banksy-signed.png
Manifest store size = <bytes>
<validation results>
```

`signingCredential.untrusted` is expected for the default self-managed hierarchy unless the verifier is explicitly configured to trust the local root. `c2patool` is not invoked by the application.
