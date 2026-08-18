# M2 license and notice approval request

**Candidate:** `feature/m2-06-backend-dependencies` at `9490ffd` or later

**Status:** Approved on 2026-08-18 by Mike Davies (`LoganAvatar`) as project,
security/license, and release owner. The encoded decision is retained in
`docs/security/license-evidence/m2-license-review-decision.md`.

## Why approval is required

The fail-closed M2 policy allows only its initially approved permissive set and
requires retained notice/attribution evidence. The exact lock and image are
technically clean of critical/high vulnerabilities. CI remained red until the
additional expressions and retained notice bundle received the owner approval
now recorded below.

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
`sha256:19e9d3e8eec1a3ca09f53b8283c99b4140fd47f3f0dfe50013288624df53c49f` is
package-manager-free and runs exact Node `24.19.0`; its vulnerability posture
must be confirmed by a fresh exact-digest Grype scan. Its non-initial license
review set is:

| Component/version                                                    | SPDX expression                           | Requested disposition/evidence                                                                        |
| -------------------------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `chownr@3.0.0`, `minipass@7.1.3`, `tar@7.5.22`, `yallist@5.0.0`      | `BlueOak-1.0.0`                           | Review as permissive and retain texts                                                                 |
| `glibc@2.43-r13`, `glibc-locale-posix@2.43-r13`, `ld-linux@2.43-r13` | `LGPL-2.1-or-later`                       | Review dynamic-linking and source/notice obligations                                                  |
| `libgcc@16.1.0-r4`, `libstdc++@16.1.0-r4`                            | `GPL-3.0-or-later WITH GCC-exception-3.1` | Review the exact exception branch and retain source/notice evidence                                   |
| `ca-certificates-bundle@20260413-r1`                                 | `(MPL-2.0 AND MIT)`                       | Review both terms and retain evidence                                                                 |
| `node@24.19.0`                                                       | scanner `NOASSERTION`                     | Review an exact MIT assertion against `/licenses/node/LICENSE`; do not suppress without that evidence |

The project MIT license and upstream Node license are copied into the runtime at
`/licenses/staticdeploy/LICENSE` and `/licenses/node/LICENSE`. The deterministic
runtime notice candidate is retained at
`docs/security/license-evidence/m2-runtime-third-party-notices.txt` with digest
`sha256:37966c1aa67cf92abd7733ee2c71753dc8908a88f3df011974b9be61c8bc5bf3`. The
image build regenerates and byte-compares it before shipping it at
`/licenses/THIRD_PARTY_NOTICES.txt`. It contains the exact production npm
closure's retained texts or package/version/manifest-digest-bound fallback
evidence, Node/application texts, standard base-runtime texts, and the GCC
Runtime Library Exception 3.1 text pinned from SPDX license-list-data commit
`5bf6d9610255540bfbee6890765a616042bf1e11`. Its approval is exact-component and
exact-digest bound in `config/license-policy.json`; any drift remains fail
closed.

## Approval recorded

Mike Davies (`LoganAvatar`) approved every disposition above, the selected `OR`
branches, the exact Node assertion, the notice and component evidence, the
source-retention publication gate, and the repository-controlled evaluator
bootstrap. This owner approval is encoded fail-closed in
`config/license-policy.json`; future component, version, expression, evidence,
or digest drift requires a new review.
