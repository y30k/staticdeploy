# StaticDeploy M3 trust contracts and threat model

- **Status:** Logical contracts approved for M3 implementation on 2026-08-18
- **Approver:** Mike Davies (`LoganAvatar`)
- **Scope:** M3-01; ADR-003 through ADR-012
- **Implementation status:** Design only. The four-command runtime, v2 schema,
  sessions, storage policies, projection, Compose, and Helm controls remain M3
  implementation work.

## Decision summary

ADR-003 through ADR-012 are accepted as the logical security and operator
contract for M3. The already-approved ADR-013 is a supplemental rollback and
recovery dependency, not an expansion of M3-01 scope. These decisions do not
attest that future controls already exist. Concrete production trust anchors
remain `BLOCKED-EXTERNAL` under B-OKTA, B-DNS, B-PG, and B-S3; production
signing-key delivery and lifecycle remain part of B-DEPLOY. Disposable
PostgreSQL/MinIO credentials, mock identity providers, loopback hosts, and local
image evidence never satisfy those blockers.

The project accepts these additional exact decisions:

1. Portal sessions use a `__Host-` Secure, HttpOnly, Path `/`, no-Domain cookie
   with `SameSite=Lax`. Every unsafe API request requires an exact trusted
   portal `Origin` and a synchronizer CSRF token bound to the server session.
   Structured API bodies use JSON; declared file streams use only their
   endpoint's exact non-simple `application/octet-stream` media type. Multipart,
   form-encoded, text/plain, missing, and endpoint-mismatched types fail before
   side effects. The OIDC callback GET is the only CSRF exemption. Its one-time
   state is bound to the initiating browser's `__Host-staticdeploy_oidc_tx`
   cookie and PKCE verifier. That cookie is Secure, HttpOnly, Path `/`, has no
   Domain, uses `SameSite=Lax`, expires within five minutes, contains only a
   random transaction ID, and is atomically consumed with the server-side state
   record on callback. Nonce, exact redirect URI, issuer/audience/signature/time
   validation, and callback replay rejection still apply.
2. A preview capability is a compact asymmetric JWS with a purpose-specific
   `kid`, at least 192 bits of random `jti`, issuer, preview audience,
   normalized host, application/release IDs, `iat`/`nbf`, `exchange_exp` no more
   than 60 seconds, and `session_exp` no more than ten minutes. `control` signs
   it; `content` has only the preview verification public-key set. URL exchange
   is intentionally replayable inside the 60-second window because content has
   no shared database. On exchange, content stores the same signed token in a
   Secure, HttpOnly, host-only, Path `/`, `SameSite=None` preview cookie, then
   returns a 303 stripped URL before subresources load. Cookie validation uses
   `session_exp`; URL validation also requires `exchange_exp`. Preview is
   embedded only from the exact portal under CSP and sandbox. There is no
   top-level fallback because it would lose the sandbox/opener/storage boundary;
   browsers that block the approved preview cookie fail closed with no content
   preview. B-DNS must validate registrable-site and supported-browser behavior.
3. Preview exchange and all preview responses use `Cache-Control: no-store` and
   `Referrer-Policy: no-referrer`. Product/application logs and telemetry strip
   query strings. Complete exclusion at ingress/CDN cannot be claimed until
   B-DNS proves query redaction, cache bypass, and no query capture before the
   application receives the request.
4. G-M4 owns an `ISO-01` minimum isolation baseline, not M5's sealed-content
   `POL-02`: `default-src 'self'`; `connect-src`, `form-action`, `object-src`,
   `base-uri`, and `worker-src` are `'none'`; scripts/styles/images/fonts are
   same-origin only. Published HTML/assets/errors use `frame-ancestors 'none'`;
   preview HTML/assets/errors name only the exact portal origin. The portal
   iframe sandbox allowlist is exactly `allow-scripts allow-forms`; it omits
   same-origin, popup, opener, top-navigation, download, presentation, and
   storage-access tokens. TM-ISO-01 proves portal control/navigation/opener and
   popup denial. M5-04/POL-02 adds manifest-derived hashes and the complete
   sealed policy. Externally reachable M4 is prohibited until ISO-01 passes.
5. Every routing generation and tombstone is signed by the worker's distinct
   routing key. The envelope binds routing ID, normalized host, application ID,
   release ID or tombstone, immutable manifest digest/prefix, generation, key
   ID, and issue time. Content has only routing verification keys and verifies
   every cross-field/object-prefix relationship. It maintains a per-process
   monotonic generation watermark and rejects in-process rollback. A new or
   lagging replica that has not observed the latest generation cannot
   distinguish replay of an older valid signed `current.json`; B-S3
   version/audit evidence and reconciliation must detect that residual
   privileged-store replay.
6. Preview and routing keys are asymmetric and purpose-separated. `control`
   alone receives preview private-key access; `worker` alone receives routing
   private-key access; `content` receives both public sets. Both purposes use
   Ed25519 with protected `alg=EdDSA`, a purpose-specific `typ`, and exactly one
   recognized `kid`; verification selects an expected key/purpose before
   checking the signature and rejects `none`, any other algorithm, missing,
   malformed, duplicate or unknown `kid`, duplicate protected-header members,
   and every unsupported `crit` header. Keys have distinct audiences, IDs,
   storage policies, rotation overlap, revocation, and compromise runbooks.
   B-DEPLOY blocks production until delivery, storage, rotation, revocation, and
   emergency replacement are provisioned and tested.

## Assets and adversaries

Protected assets are OIDC tokens and session state; role/group bindings;
application/release/audit metadata; quarantine uploads; immutable source and
served objects; routing generations; signing keys; workload and CI credentials;
backup/restore material; and retained security evidence.

Adversaries include unauthenticated browsers, malicious or compromised internal
users, hostile active content, malformed uploads/archives, compromised workload
or CI credentials, object-store tampering, concurrency/fault injection, and
operator error. No uploaded server code executes.

## Trust zones and identity contract

| Zone/identity            | May access                                                                                                                 | Must never access                                                                       | Owning evidence                     |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------- |
| Portal browser           | Portal origin, opaque session/CSRF interfaces                                                                              | OIDC tokens, storage credentials, content signing keys                                  | M3-06/07, AUTH-01–06, AUTHZ-01      |
| `control`                | Session/app DB role; quarantine upload declaration/write; PostgreSQL desired routing/outbox; preview signing-key reference | Release/routing object-store writes; routing private key; migration role; worker leases | M3-06/07, M4 API stories, TM-KEY-01 |
| `worker`                 | Worker DB role; quarantine read/delete; immutable release/routing writes; routing signing-key reference                    | Portal session/preview private key; migration role; content request identity            | M3-04/05/08, TM-KEY-01              |
| `content`                | Routing/release read; preview and routing verification public-key sets                                                     | PostgreSQL, OIDC, quarantine, object writes, every signing private key                  | M3-09, M4-09, TM-KEY-01             |
| `migrate`                | Short-lived additive migration DB role                                                                                     | Object storage, OIDC, serving traffic                                                   | M3-02/03/09                         |
| PR CI                    | Checked-out source, disposable fixtures, read-only repository token                                                        | Production secrets, registry publication, deployment                                    | M2 gate, REL-01                     |
| Protected release/deploy | Exact approved digest and scoped environment identity                                                                      | Mutable/unverified artifacts or unapproved targets                                      | M2-09/M6; B-GH/B-DEPLOY             |
| Operators                | Approved migration, binding, publish/rollback/reconciliation actions                                                       | Undocumented break-glass, silent immutable repair, pre-retention deletion               | M3/M4/M6 operator gates             |

Current `staticdeploy` still has one legacy server command. The four identities
above are target contracts, not current runtime evidence. Current Actions is CI
only; no release/deploy/promote/rollback identity is claimed. The configured
canonical branch is `main`; M2 refetched its required checks, while broader
release-environment/protected-identity evidence remains B-GH. Historical
evidence that names `master` is not an accepted current trust assertion. Obvious
PostgreSQL/MinIO test values are disposable fixtures and are forbidden as
production credentials.

## Abuse-case register

| ID       | Severity | Abuse/failure                                                                        | Required fail-closed result                                                                                                                             | Contract / owner / test                     |
| -------- | -------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| ORG-01   | High     | Spoofed Host or forwarded host reaches another app/portal                            | Trust only configured proxy boundary; unknown/wrong host is 4xx with no lookup leak                                                                     | ADR-006; M3-09/M4-09; R5/R11, PROJ-06       |
| ORG-02   | High     | Hostile published app reads portal cookie/storage or frames portal                   | Per-app origin, no portal cookie scope, frame/storage/cross-origin denial                                                                               | ADR-006; M4-09/12; content-security         |
| ORG-03   | High     | Persistent service worker controls a published origin across release transitions     | B-DNS proves a fresh never-used origin; worker-src denies registration; any origin with prior worker capability is permanently retired and never reused | ADR-006; M4-09; TM-ISO-01                   |
| SES-01   | Critical | Code/state/nonce/PKCE/callback replay or issuer confusion                            | Reject before session creation; no token/log leakage                                                                                                    | ADR-005; M3-06; AUTH-01–05, TM-SES-01       |
| SES-02   | High     | Session fixation, stale/revoked/expired session, key rotation                        | Rotate on login/privilege change; reject and revoke safely                                                                                              | ADR-005; M3-06; AUTH-02/03                  |
| CSRF-01  | High     | Cross-origin unsafe request, missing/forged token, simple content type               | Require exact Origin, synchronizer token, expected method/content type before side effects                                                              | ADR-005/010; M3-06; AUTH-04, TM-SES-01      |
| AUTHZ-01 | Critical | Unknown/stale group or binding replacement escalates actor                           | Unknown grants nothing; transactional replacement; actor cannot grant beyond authority                                                                  | ADR-005/010; M3-07; AUTHZ-01                |
| PATH-01  | Critical | Absolute/traversal/NUL/encoding/case/Unicode collision                               | Reject declaration/upload/archive before object finalization                                                                                            | ADR-007; M3-04/M4-04/M5-01; STO-03/ZIP-01   |
| UP-01    | High     | Undeclared/duplicate/missing/oversized upload or digest mismatch                     | Stream only declared bounded files to quarantine; fail exposes no release                                                                               | ADR-007/008; M3-04/05/M4-04/05; STO/JOB     |
| ARC-01   | Critical | Link/device/encrypted/malformed/bomb archive exhausts or escapes worker              | Preserve original; bounded extraction; reject with no release prefix                                                                                    | ADR-007; M5-01; ZIP-01, B-CONTENT           |
| PRE-01   | High     | Tampered/expired/wrong-host/app/release preview capability                           | Verify protected header, purpose key, signature, scope and clocks; issue no cookie                                                                      | ADR-006; M4-09; TM-PRE-01, TM-KEY-01        |
| PRE-02   | High     | Capability leaks in referrer/log/cache/history or is replayed late                   | Strip before load; no-store/no-referrer/app redaction; B-DNS ingress redaction                                                                          | ADR-006/012; M4-09; TM-PRE-01               |
| PRE-03   | High     | Stolen preview cookie is replayed within its ten-minute validity                     | Bind host/app/release/audience; Secure/HttpOnly host scope; revoke key on compromise                                                                    | ADR-006; M4-09; TM-PRE-01                   |
| KEY-01   | Critical | Preview/routing key compromise or cross-purpose key use forges access/routing        | Distinct key purposes/audiences/identities; wrong-key denial; emergency rotation                                                                        | ADR-004/006/009; TM-KEY-01, B-DEPLOY        |
| STO-01   | Critical | Control/content crosses quarantine/release/routing policy                            | Component policy denies every forbidden prefix/action                                                                                                   | ADR-004/007; M3-04/09; STO-01, B-S3         |
| STO-02   | Critical | Overwrite/corrupt READY release                                                      | Create-only finalization, read-back SHA-256, immutable READY fields                                                                                     | ADR-007; M3-04/M4-05; STO-02                |
| JOB-01   | High     | Duplicate/stale worker or timeout causes conflicting completion                      | Atomic lease/renew/reclaim, attempt bounds, idempotent result identity                                                                                  | ADR-008; M3-05; JOB-01–03                   |
| PROJ-01  | Critical | Out-of-order/forged/cross-app routing generation serves wrong release                | Conditional generation, signed bound envelope, read-back ack, stale rejection                                                                           | ADR-009; M3-08/M4-08/09; PROJ-01–06         |
| PROJ-02  | High     | Storage/read-back outage replaces known-good routing                                 | Leave operation pending/failed and serve last verified generation                                                                                       | ADR-009; M3-08; PROJ-03/05                  |
| PROJ-03  | High     | Privileged storage actor replays an older valid signed generation                    | Reject below memory watermark; detect version rollback; cold-start replay stays residual                                                                | ADR-009; M3-08; TM-PROJ-01                  |
| CI-01    | Critical | PR/fork/tag spoof publishes or receives credentials                                  | Read-only untrusted CI, exact-commit gate, no publish identity                                                                                          | ADR-011; M2/M6; REL-01                      |
| ID-01    | Critical | One workload receives all credentials or wrong command starts                        | Command-specific schemas/roles; wrong/missing host/credential fails startup                                                                             | ADR-004/011; M3-09–11; CMD-01/CMP-01/HLM-01 |
| OP-01    | Critical | Operator self-escalates, reuses migration role, bypasses promotion/rollback approval | Role check/audit first; short-lived identities; protected approval; no mutation on denial                                                               | ADR-008–013; M3/M4/M6 gates                 |
| AUD-01   | High     | Actor alters/omits audit records or leaks secrets in denial evidence                 | Append-only constraints; success/denial records; bounded redacted actor/target/result/UTC                                                               | ADR-010/013; TM-AUD-01                      |
| REC-01   | High     | Reconciler silently repairs/deletes immutable content                                | Report only; destructive repair/deletion needs explicit approved action and retention                                                                   | ADR-007/009/013; M6-08; REC-01/02           |
| OBS-01   | High     | Secrets/PII/high-cardinality values leave process or telemetry outage blocks service | Redact/drop/bound; exporters disabled; telemetry failure non-blocking                                                                                   | ADR-012; M6-09/10; OBS-01–04, B-EYES        |

## Required negative evidence

Implementing stories must add exact negative cases rather than relying on this
review. At minimum:

- session: absent/invalid CSRF, wrong Origin, callback replay, login CSRF,
  revoked/expired/fixed sessions, unknown groups, and browser-simple body types;
- preview (`TM-PRE-01`): tampered, expired, wrong host/app/release, old/wrong
  purpose key, post-window replay, in-window theft, cookie replay,
  referrer/application/proxy/CDN log and cache leakage, third-party-cookie
  denial, and capability removal before subresources;
- browser isolation (`TM-ISO-01`): exact preview/published/error
  `frame-ancestors`, no service-worker persistence, and denial of connect, form,
  object, base, and worker capabilities;
- storage/content (`TM-PROJ-01`): every forbidden action/prefix,
  cross-application routing/object substitution, signature/key-ID/purpose/
  prefix/manifest mismatch, stale and valid-old generation replay, and
  last-known-good behavior;
- key lifecycle (`TM-KEY-01`): missing/wrong/cross-purpose/expired/revoked keys,
  overlap rotation, compromise response, and private-key exposure to the wrong
  workload;
- M3 authorization/audit (`TM-AUD-01`): self-escalation, forged idempotency
  reuse, immutable audit update/delete, success and denial records, and
  token/cookie/query/PII canaries excluded from bounded audit metadata;
- workload/delivery/operator: wrong command identity and migration-role reuse
  use CMD-01/CMP-01/HLM-01; fork/tag spoof and mutable digests use REL-01;
  unapproved promotion uses DEP-03; rollback evidence and approval use DEP-04
  and CUT-01; break-glass issuance/approval/expiry/revocation/use and protected
  actor/approver/from/to evidence use OP-AUD-01 in M6/M7.

Every gate record must identify executed, skipped, failed, and
`BLOCKED-EXTERNAL` cases; commit and artifact digests; profile/configuration;
and residual risk. A mock pass never closes a production gate.

## External blocker register

| Gate   | Unknown concrete values                                                                                                                                                                                                                                                            | Local logical work allowed                             | Production acceptance forbidden until                                       |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------------- |
| B-OKTA | Issuer/client, redirects/logout, stable group claim/IDs, admin mapping, users, key/secret rotation                                                                                                                                                                                 | Session/RBAC implementation against mock IdP           | AUTH-06 passes with provisioned tenant and approved users/rotation          |
| B-DNS  | Portal and published/preview wildcard DNS/TLS, registrable-site/browser matrix, trusted proxy chain, pre-app query-log redaction, cache bypass, fresh never-used content origins and permanent retirement after any worker allowance, exposure/viewer policy, route-cutover access | Host/origin/capability logic on reserved local domains | Real DNS/TLS/proxy/cache/log/wildcard isolation is accepted                 |
| B-PG   | Service, distinct roles, migration identity, backup destination, backup/restore owner, RPO/RTO                                                                                                                                                                                     | Disposable schema/concurrency/restore tests            | Production roles, backup, restore, and capability rehearsal pass            |
| B-S3   | Endpoint/bucket/prefix, explicit or workload provider-chain credentials, component policies, conditional/create-only/read-after-write behavior, version/audit rollback detection, encryption/versioning/retention/backups                                                          | Disposable MinIO protocol and policy tests             | Production capability/policy/provider-chain tests and owner acceptance pass |

Additional later blockers remain B-GH/B-DEPLOY for protected release/deployment
and distinct signing-key lifecycle, B-CUTOVER for route
checkpoints/windows/support/destruction approval, B-CONTENT for approved
archive/scanner limits, and B-EYES for telemetry onboarding. They are not
silently treated as satisfied by M3-01.

## Operator and rollback contract

Rollback redeploys a previously verified immutable digest, rejects incompatible
schema, reruns identical API/content smoke, and restores the approved routing
and DNS checkpoint where applicable, as required by supplemental ADR-013. Schema
remains expand-only and release objects immutable during the rollback window.
Historical migrations `00`–`02` are never run backward; crossing them requires
verified backup/restore. Reconciliation reports drift and digest mismatch but
never silently repairs immutable content. Break-glass, repair, deletion,
promotion, and rollback must be explicit, role-checked, approved, and audited.

Still-unassigned production owners are mapped explicitly: rollback operator to
B-DEPLOY and M6-01/M6-07; backup/restore owner to B-PG and M6-08/M6-10; and
route checkpoint, rollback window, support owner, and destruction approval to
B-CUTOVER and M7-03/M7-06–08. They are not implicit maintainer powers.

## Traceability

| Domain                 | ADRs            | Implementation stories          | Required evidence                                 |
| ---------------------- | --------------- | ------------------------------- | ------------------------------------------------- |
| v2/data/API            | ADR-003/008/010 | M3-02/03/05, M4-01–03/08        | SCH-01–05, JOB-01–03, API-01–03                   |
| Workload identity      | ADR-004/011     | M3-09–11                        | command boot/config-negative, IMG-02, DEP-01/02   |
| Sessions/authz         | ADR-005/010     | M3-06/07, M4-03                 | AUTH-01–06, AUTHZ-01, API-03                      |
| Origins/preview        | ADR-006         | M3-09, M4-09/12                 | R5/R11, TM-PRE-01, TM-ISO-01, POL-03, PROJ-06     |
| Upload/storage/archive | ADR-007/008     | M3-04/05, M4-04–07, M5-01/02    | STO-01–03, JOB-01–03, DIR-01, ZIP-01/02           |
| Projection             | ADR-009         | M3-08, M4-08/09                 | PROJ-01–06, TM-PROJ-01, TM-KEY-01                 |
| CI/release/deploy      | ADR-011/013     | M2-09, M3-10/11, M6 delivery    | REL-01, DEP-01–04, REC-01/02, R13/R14/R16         |
| Operators/audit        | ADR-008–013     | M3-07/08, M4-02/03/08, M6-07/08 | AUTHZ-01, API-03, SCH-04/05, TM-AUD-01, OP-AUD-01 |
| Telemetry              | ADR-012         | M6-09/10                        | OBS-01–04, OPS-01, Eyes onboarding                |

## Review disposition

The logical ADRs and the exact decisions in this document are approved. The
following are not implementation claims:

- four-command runtime or workload credential separation;
- v2 schema, session, upload, projection, Compose, or Helm behavior;
- production Okta, DNS/TLS, PostgreSQL, S3, signing keys, GitHub release,
  deployment, cutover, or Eyes capability.

M3-02 through M3-11 must satisfy their executable contracts. B-OKTA, B-DNS, B-PG
and B-S3 remain open for production-like acceptance. The accepted preview
residual is theft/replay within the 60-second URL or ten-minute cookie window
despite at least 192-bit entropy and strict scope; rotation/revocation is the
emergency response. Valid signed projection rollback after a cold start is also
residual until B-S3 version/audit evidence and reconciliation detect it. Public
preview and published-content exposure remain prohibited until B-DNS and
TM-ISO-01 evidence pass.
