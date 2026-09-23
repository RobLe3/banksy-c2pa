# Trust model

The default credential is a private, local public-key infrastructure. It provides cryptographic provenance for the operator's own workflow; it does not create public C2PA identity trust.

## Separate questions

The CLI reports these properties separately:

1. Is an embedded manifest present?
2. Do its claim signature and asset binding validate?
3. Does its certificate chain validate against the configured local root?
4. Is public C2PA trust established?
5. Is there a trusted RFC 3161 timestamp?

A normal local result is valid cryptography, valid local trust, no public trust, and no trusted timestamp. `verify --trust-local-root` adds `~/.config/banksy-c2pa/certs/root-ca.pem` only for that operation. It never presents the local decision as trust from the official C2PA ecosystem.

## Identity fields

A new profile requires a signer name. Organization, domain, URI, and manifest vendor are optional. When configured, the organization appears in the certificate subject; domain and URI appear as certificate subject alternative names and signed manifest metadata; vendor appears in the manifest definition. Because `c2pa-rs` 0.90 expects an Organization attribute when reading a verified signing certificate, the certificate repeats the required signer name in that attribute when no separate organization was configured. The profile and JSON reports still show the optional organization as unconfigured.

These fields are self-asserted under the local root. They do not independently establish domain control, legal identity, authorship, copyright ownership, accuracy, or affiliation with any person or organization. The claim-generator product is always `banksy-c2pa`; it is separate from the user-configured signer identity.

## Existing profiles

Profiles created by older versions may contain `service_name` and the earlier Banksy-themed example identity. The loader treats `service_name` as `signer_name`. `init` preserves existing profile values and certificates, and identity options are accepted only when a profile is first created. Rotation issues a new leaf under the existing root and identity.

## Public trust

Public trust would require a suitable C2PA claim-signing certificate and chain recognized by the intended verifier or trust list, together with the relevant conformance and certificate-enrollment requirements. A domain name alone is not enough. Touch ID can authorize a local key retrieval, but it does not establish public C2PA trust.

A future public-trust backend should replace credential provisioning and signing-key access without changing the provenance policy: unchanged assets use `attest`; genuine edits use `derivative` with a parent.
