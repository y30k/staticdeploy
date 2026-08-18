# M2 license and notice approval request

**Candidate:** `feature/m2-06-backend-dependencies` at `3f2e841` or later

**Status:** Blocking decision; no approval or waiver is implied by this
document.

## Why approval is required

The fail-closed M2 policy allows only its initially approved permissive set and
requires retained notice/attribution evidence. The exact lock and image are
technically clean of critical/high vulnerabilities, but CI must remain red until
a security/license owner reviews the additional expressions and a release owner
accepts the retained notice bundle.

## Exact source/development graph inventory

The current Yarn manifest inventory contains 1,336 records. Initially approved
expressions account for 1,295 records. The remaining review set is:

| SPDX expression           | Count | Typical owner/purpose                       | Requested disposition                             |
| ------------------------- | ----: | ------------------------------------------- | ------------------------------------------------- |
| `BlueOak-1.0.0`           |    20 | Current npm filesystem/glob utilities       | Review as permissive                              |
| `MPL-2.0`                 |    12 | Vite `lightningcss` platform/build packages | Review build-only file-level copyleft obligations |
| `MIT-0`                   |     2 | CSS tooling                                 | Review as permissive                              |
| `(MIT OR CC0-1.0)`        |     2 | `type-fest`                                 | Select `MIT`                                      |
| `CC-BY-4.0`               |     1 | `caniuse-lite` data                         | Review attribution requirement                    |
| `CC-BY-3.0`               |     1 | SPDX exception data                         | Review attribution requirement                    |
| `WTFPL`                   |     1 | retained CommonJS `chai-as-promised`        | Approve development-only or require replacement   |
| `Python-2.0`              |     1 | `argparse` under YAML/tooling dependencies  | Review development-only notice obligations        |
| `(BSD-2-Clause OR WTFPL)` |     1 | retained CommonJS `sinon-chai`              | Select `BSD-2-Clause`                             |

## Exact runtime image inventory

Image configuration digest
`sha256:968d0cdc29245c1d2ccf72638b6803efccb941b9ee4caafc3d2df164640c36a6` is
package-manager-free, runs exact Node `24.19.0`, and has zero current Grype
findings. Its non-initial license review set is:

| Component/version                                                    | SPDX expression                           | Requested disposition/evidence                                                                        |
| -------------------------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `chownr@3.0.0`, `minipass@7.1.3`, `tar@7.5.22`, `yallist@5.0.0`      | `BlueOak-1.0.0`                           | Review as permissive and retain texts                                                                 |
| `glibc@2.43-r13`, `glibc-locale-posix@2.43-r13`, `ld-linux@2.43-r13` | `LGPL-2.1-or-later`                       | Review dynamic-linking and source/notice obligations                                                  |
| `libgcc@16.1.0-r4`, `libstdc++@16.1.0-r4`                            | `GPL-3.0-or-later WITH GCC-exception-3.1` | Review the exact exception branch and retain source/notice evidence                                   |
| `ca-certificates-bundle@20260413-r1`                                 | `(MPL-2.0 AND MIT)`                       | Review both terms and retain evidence                                                                 |
| `node@24.19.0`                                                       | scanner `NOASSERTION`                     | Review an exact MIT assertion against `/licenses/node/LICENSE`; do not suppress without that evidence |

The project MIT license and upstream Node license are copied into the runtime at
`/licenses/staticdeploy/LICENSE` and `/licenses/node/LICENSE`. A complete
third-party notice artifact for all accepted source and image components still
must be generated, reviewed, digest-recorded in `config/license-policy.json`,
and uploaded beside policy evidence.

## Approval needed

Provide either:

1. named security/license and release-owner approval for each disposition above,
   including the selected `OR` branches and Node assertion, plus authorization
   to record the reviewed notice artifact; or
2. rejection/replacement instructions for any expression.

Approval must also identify who may perform the bootstrap review of the
repository-controlled PR evaluator. Self-approval by the implementing agent is
not valid.
