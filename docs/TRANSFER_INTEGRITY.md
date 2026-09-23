# Transfer integrity

Image-upload services may decode and re-encode PNG or JPEG files. Visible pixels can remain the same while C2PA container data is removed. A `.banksy-signed` filename therefore is not evidence that the received bytes still contain a credential.

## Example diagnosis

In a local test, signed files contained one CRC-valid PNG `caBX` chunk before `IDAT`, a valid local claim, and a preserved upstream manifest. Copies retrieved through an image-attachment route contained only ordinary image chunks and had different complete-file hashes. That evidence supported a transfer-path transformation in that test; it does not imply that every service or every upload path strips C2PA metadata.

The public repository intentionally omits the private artwork, exact filenames, local certificate identity, and file hashes from that test.

## Check exact bytes

Audit the file that will be sent and the file that was received:

```bash
banksy-c2pa audit image.banksy-signed.png
banksy-c2pa audit image.banksy-signed.png --expect-sha256 <expected-hash>
c2patool image.banksy-signed.png
```

For a signed PNG, the audit should report an embedded `PNG caBX` store, valid chunk structure and CRCs, a valid claim signature and asset binding, and local trust when the configured root is available. A managed `.banksy-signed` file without that credential is invalid regardless of its filename or appearance.

## Deliver without image processing

Create an evidence archive and upload it as an opaque file or document:

```bash
banksy-c2pa package image.banksy-signed.png -o delivery.zip
banksy-c2pa audit delivery.zip
```

After download, compare the ZIP hash and audit it again. Extracted image hashes must match `SHA256SUMS` and `evidence.json`. The included root certificate enables cryptographic checking but does not authenticate itself; compare its fingerprint through a separate trusted channel.

The [C2PA 2.4 specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_png) defines the PNG manifest store in a `caBX` chunk.
