# C2PA profile

## Product and signer identity

The claim-generator product name is always `banksy-c2pa`, with the Cargo package version. This identifies the software that created the claim. It is separate from the user-configured signer identity in the certificate.

A signer name is required when a profile is first created. Organization, domain, URI, and manifest vendor are optional. If configured, the domain and URI are also signed custom claim-generator fields:

```text
com.roblemumin.banksy-c2pa.domain
com.roblemumin.banksy-c2pa.uri
```

These custom fields and the certificate identity are assertions under a local root. They are not substitutes for public C2PA trust.

## Attestation

An attestation states that the configured signer made the supplied editorial or publication assertion. It does not state that the signer created the image or changed visible content.

For an unsigned source, the tool uses a standard edit manifest. The source becomes the sole `parentOf` ingredient and the action sequence is:

```text
c2pa.opened
c2pa.edited.metadata
c2pa.published    # only with --published
```

For a source with a valid active manifest, the tool uses an update manifest with the same restricted action set. The C2PA library connects the update to the previous active manifest. Decoded RGBA16 pixels must match before the output is committed.

The tool never emits `c2pa.edited` in attestation mode.

## Derivative

A derivative requires `--parent` and `--input`. Their decoded RGBA16 hashes must differ. The parent becomes a `parentOf` ingredient, including its existing manifest store when present, and the action sequence is:

```text
c2pa.opened
c2pa.edited
c2pa.published    # only with --published
```

`allActionsIncluded` is false because the CLI did not observe the editing process and must not imply a complete edit log. A free-form description supplies editorial context without inventing unobserved transformation details.

The signed output must decode to the same pixels as the edited input. An edited input with its own active manifest is rejected to avoid constructing an ambiguous second parent chain.

## Validation policy

An existing parent manifest may be cryptographically valid but publicly untrusted. It is accepted because validity and public trust are separate properties. An invalid parent is rejected.

Before commit, a temporary output must:

- have a valid active manifest;
- validate against the configured private root;
- contain the expected actions and a `parentOf` ingredient;
- retain the provided input pixels;
- omit `c2pa.edited` in attestation mode;
- contain one structurally valid embedded C2PA store in the expected PNG or JPEG location; and
- contain one more manifest than the provenance source, with an existing source manifest reachable through the parent ingredient.

The committed file is reopened and checked again. Its complete SHA-256 is included in the signing report.
