# Chainguard runtime component compliance evidence

**Status:** Technical evidence candidate; named security/license and
release-owner review is still required. This document does not declare
obligations complete.

## Exact subject

- Runtime base:
  `cgr.dev/chainguard/glibc-dynamic@sha256:df4e22a4b5dcd8e15a51fe9b04e16717d411dd9f4fe4b3844c1bf425b14be303`
- Current derived image configuration at evidence generation:
  `sha256:19e9d3e8eec1a3ca09f53b8283c99b4140fd47f3f0dfe50013288624df53c49f`
- Architecture: `amd64` only; multi-architecture evidence belongs to M2-08.
- Base package declaration: inherited `/etc/apko.json` in the image.

The image conformance test byte-compares each inherited package SBOM below with
the retained copy. A future base or package change therefore fails until this
evidence is regenerated and reviewed.

| Component                            | Expression                                | Retained base SBOM SHA-256                                         |
| ------------------------------------ | ----------------------------------------- | ------------------------------------------------------------------ |
| `ca-certificates-bundle@20260413-r1` | `MPL-2.0 AND MIT`                         | `048e54383819dc88c3e7015bed9f671b51ba3c649fff590b9ca1b8124c4fb0dd` |
| `glibc@2.43-r13`                     | `LGPL-2.1-or-later`                       | `1f4233fd035591b1dd4f23537a6ff7c09ddd928482908067baba07dc8e19610e` |
| `glibc-locale-posix@2.43-r13`        | `LGPL-2.1-or-later`                       | `68fa41c5f5c8b02e3a91c983dd8efa4a0316db7d4b3f711eadfdb4a7cef76220` |
| `ld-linux@2.43-r13`                  | `LGPL-2.1-or-later`                       | `3af9e0b1cf6cd659bb027d4b7aedf8673eee96f39a102377958095b3f697d685` |
| `libgcc@16.1.0-r4`                   | `GPL-3.0-or-later WITH GCC-exception-3.1` | `d9ca803e39b73744a8f9cb348d41bf7b3ed537da634d7c8166f5d0e15cde4bf2` |
| `libstdc++@16.1.0-r4`                | `GPL-3.0-or-later WITH GCC-exception-3.1` | `9c09f88a89cb340798aeb14dd8008307b5652ba4fd9e91b597d3d7dec843969b` |

## Exact source locations

The inherited Chainguard SBOMs identify both build recipes and immutable source
revisions. Source availability was checked on 2026-08-18 UTC.

### CA certificates

- Upstream revision: Alpine `ca-certificates` commit
  `721ff6606b8c145755691d6cf87088ae7ff3d346`.
- Content-addressed source:
  `https://tarballs.cgr.dev/a/f7f6555663adc30d4e3c43a90ddef6942dabe93d06f7a7201cf29d993222346a-721ff6606b8c145755691d6cf87088ae7ff3d346.tar.gz`
- Observed availability: HTTP 200, 313,972 bytes.

### glibc, loader, and POSIX locale

- Upstream revision: GNU glibc commit
  `dae425b554207f7c4599c7fac707ad4c08545674`.
- Content-addressed source:
  `https://tarballs.cgr.dev/g/9390037ac2ec26cf74ce7c6709d852e0ce67205355e04fbdb9b9549f47a5bb40-dae425b554207f7c4599c7fac707ad4c08545674.tar.gz`
- Observed availability: HTTP 200, 40,582,149 bytes.

### libgcc and libstdc++

- Upstream revision: GNU GCC commit `6afcc4f6da931eb93f3ab001a0dd9650ea71d1ea`,
  release `releases/gcc-16.1.0`.
- Chainguard SBOM source URL:
  `https://tarballs.cgr.dev/g/dc3e72361e36d33e861a0662815d63a4f1b8578521cc6935343a4aa87327bdec-6afcc4f6da931eb93f3ab001a0dd9650ea71d1ea.tar.gz`.
  This URL returned HTTP 404 during the check and is not relied on alone.
- Available exact-revision archive:
  `https://gitlab.com/gnutools/gcc/-/archive/6afcc4f6da931eb93f3ab001a0dd9650ea71d1ea/gcc-6afcc4f6da931eb93f3ab001a0dd9650ea71d1ea.tar.gz`
  (HTTP 200 during the check).

The release owner must choose and retain an approved source-availability
mechanism for the release lifetime. The policy remains closed until that choice
and its retention period are reviewed.

## Linking and exception applicability evidence

The exact Node binary is dynamically loaded. Running the inherited loader as:

```text
/usr/lib/ld-linux-x86-64.so.2 --list /nodejs/bin/node
```

reported shared dependencies including `/usr/lib/libc.so.6`,
`/lib/libstdc++.so.6`, and `/lib/libgcc_s.so.1`. StaticDeploy adds JavaScript
and compiled JavaScript only; it does not modify or statically combine the
inherited GNU libraries. The shared objects remain replaceable in a derived
image layer.

Exact runtime file SHA-256 values at evidence generation:

| File                            | SHA-256                                                            |
| ------------------------------- | ------------------------------------------------------------------ |
| `/nodejs/bin/node`              | `bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12` |
| `/usr/lib/ld-linux-x86-64.so.2` | `3be699384f515ad4ab005d3a85ea935df43a6d3820f3a28fb50409d0d272ef8e` |
| `/usr/lib/libc.so.6`            | `92469e5ec21ef48909be9425ad5011d6f4ebd820b68dd0a4c451a93ce9dfa105` |
| `/usr/lib/libgcc_s.so.1`        | `41e65c93c8a1c60543e9d8c03a47f0f202bb8645a375f2ef2f476f94ad53bcf1` |
| `/usr/lib/libstdc++.so.6.0.35`  | `6dbb840b5a72c29e2faef9213c72e5a8b01282eb033a3e264648baebf5f93e43` |

The package SBOMs explicitly declare the GCC runtime libraries as
`GPL-3.0-or-later WITH GCC-exception-3.1`; the exact exception text is retained
at `base-runtime-license-texts/GCC-exception-3.1.txt` and in the shipped notice
bundle. A named license owner must confirm that this evidence is legally
sufficient for the actual binaries; the implementation does not self-approve
that conclusion.

## Shipped texts and residual decision

The image ships:

- `/licenses/staticdeploy/LICENSE`;
- `/licenses/node/LICENSE`;
- `/licenses/THIRD_PARTY_NOTICES.txt`, including GPL, LGPL, MPL, MIT-family,
  Apache, CC0, and GCC Runtime Library Exception texts and the exact production
  npm notices.

Technical evidence now identifies exact package versions, inherited SBOM bytes,
source revisions/locations, dynamic linking, binary hashes, and shipped texts.
The remaining decision is owner review of source-retention duration, LGPL
recipient/relinking sufficiency, GCC exception applicability, CA attribution,
and the Node scanner assertion.
