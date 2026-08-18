# M2 license, notice, and evaluator approval decision

**Decision date:** 2026-08-18

**Approver:** Mike Davies (`LoganAvatar`)

**Authority represented:** StaticDeploy project owner, security/license owner,
and release owner

## Decision

The project remains licensed under its existing MIT license. Third-party works
are not relicensed as MIT; they retain their native terms and are accepted only
with the notices, source references, and conditions recorded by this candidate.

The approver explicitly approved all dispositions requested in
`docs/security/m2-license-approval-request.md`, including:

- the initially allowed permissive set: `0BSD`, `Apache-2.0`, `BSD-2-Clause`,
  `BSD-3-Clause`, `CC0-1.0`, `ISC`, and `MIT`;
- `BlueOak-1.0.0`, `MIT-0`, `MPL-2.0`, `CC-BY-3.0`, `CC-BY-4.0`, `Python-2.0`,
  and `WTFPL` for their inventoried source/development uses;
- selection of `MIT` from `(MIT OR CC0-1.0)`;
- selection of `BSD-2-Clause` from `(BSD-2-Clause OR WTFPL)`;
- the runtime expressions `(MPL-2.0 AND MIT)` and
  `(GPL-3.0-or-later WITH GCC-exception-3.1)` without dropping either an `AND`
  obligation or the GCC exception;
- the exact Node `24.19.0` MIT assertion where Syft reports `NOASSERTION`, bound
  to the exact copied Node license and image component/version;
- the deterministic runtime notice artifact with SHA-256
  `37966c1aa67cf92abd7733ee2c71753dc8908a88f3df011974b9be61c8bc5bf3`;
- the component/version-bound Chainguard evidence and analysis in
  `chainguard-runtime-compliance.md`; and
- the repository-controlled evaluator and workflow as the bootstrap-reviewed
  implementation for this candidate.

Development-only packages are not included in the distributed service image.
Their SPDX expressions are accepted for build, test, and analysis use; their
native notices remain in their package sources and install cache. Runtime
components are covered by the shipped project, Node, package-specific, standard
license, and GCC exception texts retained in the deterministic notice bundle.

## Source retention and publication gate

No image or package is published by this candidate. Any later publication must
fail closed unless exact source archives for the distributed CA, glibc, loader,
libgcc, and libstdc++ versions are retained as co-versioned release artifacts
for the approved release-retention period. The exact upstream GitLab GCC commit
archive documented in `chainguard-runtime-compliance.md` is the fallback source
when the Chainguard content-addressed GCC URL is unavailable. M2-08 and later
distribution work may implement that retention mechanism but may not weaken or
silently bypass it.

## Scope

This approval completes the human decision required to encode the license policy
for the exact M2-06/M4-10/M2-07 candidate. It is not a vulnerability exception,
does not approve future dependency or base-image drift, and does not approve
publication, production deployment, or later blocked milestones.
