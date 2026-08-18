# M2-08 arm64 license and evidence extension

**Decision date:** 2026-08-18

**Approver:** Mike Davies (`LoganAvatar`)

**Authority represented:** StaticDeploy project owner, security/license owner,
and release owner

## Decision

The project remains MIT licensed and third-party components retain their native
terms. The M2 license decision is extended to the `linux/arm64` build only where
it has the same component names, versions, SPDX expressions, notices, and source
revisions as the approved `linux/amd64` runtime.

The shared runtime base is the multi-platform OCI index:

`cgr.dev/chainguard/glibc-dynamic@sha256:df4e22a4b5dcd8e15a51fe9b04e16717d411dd9f4fe4b3844c1bf425b14be303`

Its exact arm64 manifest is
`sha256:d6d2fa177d363fbf31018d8182d73927d7656a827ba42ae18724b8dcd0d12b41`. The
inherited arm64 package SBOM evidence is retained with these SHA-256 values:

| Component evidence                             | SHA-256                                                            |
| ---------------------------------------------- | ------------------------------------------------------------------ |
| `ca-certificates-bundle-20260413-r1.spdx.json` | `ab192ca51051759d28a8a234bfc77264b152d3c05d9c0ae72fafce2d33c2a768` |
| `glibc-2.43-r13.spdx.json`                     | `7040782d5677bf9ea85374533fd09dab90984206f9484cd89a1b11f58bb341ef` |
| `glibc-locale-posix-2.43-r13.spdx.json`        | `5454c842a1fde7581f7ccd580d801b2e39ba1bcee824102747363ad15993f05c` |
| `ld-linux-2.43-r13.spdx.json`                  | `e1b910a3787551a62220aa0db593fcaa2aeead60c9a8757a2b52635c93c7f7af` |
| `libgcc-16.1.0-r4.spdx.json`                   | `b92cd4f2ec37342a83f77d7915452ac78c95c8b32dd5bb679929fc4587c097d4` |
| `libstdc++-16.1.0-r4.spdx.json`                | `605d5c4ebf0c2d0a9ba478e07e41bcc501f89a16d694da472f5900aa8942879f` |
| `wolfi-baselayout-20230201-r29.spdx.json`      | `8da10c265e9a6fa93a50a9d29ed272089880298d9c7916428cdb73bfd11c3f58` |

The corresponding amd64 `wolfi-baselayout` SBOM is retained with SHA-256
`d065690a90e0c709b1be4a950adbc59439b15e8b9619a7c0e9203c82a3496dc5`. The
deterministic runtime notice bundle is regenerated and byte-compared for each
architecture. Image conformance must byte-compare the architecture-specific base
SBOMs, run exact Node `24.19.0`, and pass the same non-root/read-only/capability
restrictions on both platforms.

## Scope and publication gate

This approval does not authorize registry login, image push, manifest push,
signing, package publication, or deployment. Pull-request execution must build
and load each architecture locally, retain exact configuration digests bound to
one commit, and fail if any publication-capable workflow behavior appears.
Future component, version, expression, base-index, platform-manifest, notice, or
evidence drift requires a new review. Source-archive retention remains a later
publication prerequisite.
