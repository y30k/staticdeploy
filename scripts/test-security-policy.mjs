import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const checker = path.resolve("scripts/security-policy.mjs");
const temp = fs.mkdtempSync(
    path.join(os.tmpdir(), "staticdeploy-security-policy-")
);
const commit = execFileSync("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
}).trim();
const digest = (value) =>
    `sha256:${createHash("sha256").update(value).digest("hex")}`;
const lockDigest = digest(fs.readFileSync("yarn.lock"));
const imageDigest = `sha256:${"a".repeat(64)}`;
const now = Date.now();
const timestamp = new Date(now - 60_000).toISOString();
const databaseTimestamp = new Date(now - 2 * 60 * 60 * 1000).toISOString();
const sourceSbomRawDigest = `sha256:${"c".repeat(64)}`;
const semgrepDigest = digest(fs.readFileSync("config/semgrep.yml"));
const subject = {
    schemaVersion: 1,
    commit,
    lockDigest,
    imageDigest,
    workflow: {
        repository: "local/staticdeploy",
        runId: "fixture",
        runAttempt: "1",
        eventName: "local",
        ref: "fixture",
    },
};
const contracts = {
    "dependency-vulnerabilities": {
        name: "grype",
        version: "0.117.0",
        identity:
            "anchore/grype@sha256:ddf9e9f204049f3a4a0955ef70873cabab6a31432125ad4f20a490b54950a253",
        database: true,
        inputDigest: sourceSbomRawDigest,
    },
    "image-vulnerabilities": {
        name: "grype",
        version: "0.117.0",
        identity:
            "anchore/grype@sha256:ddf9e9f204049f3a4a0955ef70873cabab6a31432125ad4f20a490b54950a253",
        database: true,
        inputDigest: imageDigest,
    },
    "source-sbom": {
        name: "syft",
        version: "1.51.0",
        identity:
            "anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0",
    },
    "image-sbom": {
        name: "syft",
        version: "1.51.0",
        identity:
            "anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0",
    },
    sast: {
        name: "semgrep",
        version: "1.97.0",
        identity:
            "returntocorp/semgrep@sha256:a265d09a9ca712e6624aca09056304ce4314a695b7028d65c041dd53fd44c700",
        rulesetDigest: semgrepDigest,
    },
    secrets: {
        name: "trufflehog",
        version: "3.97.0",
        identity:
            "trufflesecurity/trufflehog@sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33",
        rulesetDigest:
            "sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33",
    },
    "license-inventory": {
        name: "yarn-info",
        version: "4.18.0",
        identity: "yarn@npm:4.18.0",
        rulesetDigest: lockDigest,
    },
};
const lockPackages = [
    ...fs
        .readFileSync("yarn.lock", "utf8")
        .matchAll(/^\s*resolution:\s*"((?:@[^/"]+\/)?[^@"]+)@npm:([^"]+)"/gm),
]
    .map((match) => ({ name: match[1], version: match[2] }))
    .filter(
        (item, index, values) =>
            values.findIndex(
                (candidate) =>
                    candidate.name === item.name &&
                    candidate.version === item.version
            ) === index
    );
const licenseComponents = lockPackages.map((item) => ({
    component: item.name,
    locator: `${item.name}@npm:${item.version}`,
    version: item.version,
    scope: "resolved",
    spdxExpression: "MIT",
}));
const sourceComponents = lockPackages.map((item) => ({
    name: item.name,
    version: item.version,
    purl: `pkg:npm/${encodeURIComponent(item.name).replace("%40", "@")}@${encodeURIComponent(item.version)}`,
}));

function scanner(type) {
    const contract = contracts[type];
    return {
        name: contract.name,
        version: contract.version,
        identity: contract.identity,
        rulesetDigest: contract.rulesetDigest || null,
        databaseUpdatedAt: contract.database ? databaseTimestamp : null,
        databaseValid: contract.database ? true : null,
        databaseIdentity: contract.database
            ? "v6.1.9|https://grype.example/database.tar.zst"
            : null,
        inputDigest: contract.inputDigest || null,
    };
}
const payloads = {
    "dependency-vulnerabilities": {
        target: { userInput: "source-sbom.raw.json" },
        matches: [],
    },
    sast: { results: [] },
    secrets: { findings: [] },
    "image-vulnerabilities": { target: { imageID: imageDigest }, matches: [] },
    "source-sbom": { bomFormat: "CycloneDX", components: sourceComponents },
    "image-sbom": {
        spdxVersion: "SPDX-2.3",
        name: `staticdeploy-${imageDigest.slice(7)}`,
        documentNamespace: `https://anchore.example/${imageDigest.slice(7)}`,
        packages: [
            {
                name: "fixture-image",
                SPDXID: "SPDXRef-fixture-image",
                versionInfo: imageDigest.slice("sha256:".length),
                licenseDeclared: "MIT",
                licenseConcluded: "MIT",
                externalRefs: [
                    {
                        referenceLocator: `pkg:oci/fixture?tag=${imageDigest.slice("sha256:".length)}`,
                    },
                ],
            },
        ],
    },
    "license-inventory": { components: licenseComponents },
};
function makeReport(type, payload) {
    return {
        schemaVersion: 1,
        type,
        subject: structuredClone(subject),
        scanner: scanner(type),
        startedAt: timestamp,
        completedAt: timestamp,
        exitCode: 0,
        complete: true,
        rawDigest:
            type === "source-sbom"
                ? sourceSbomRawDigest
                : `sha256:${"b".repeat(64)}`,
        payload,
    };
}
const licensePolicy = {
    schemaVersion: 1,
    allowedSpdx: ["MIT", "CC0-1.0"],
    obligationEvidence: {
        MIT: {
            obligationsComplete: true,
            evidence: "fixture MIT notice",
            reviewReference: "review-mit",
        },
        "CC0-1.0": {
            obligationsComplete: true,
            evidence: "fixture CC0 notice",
            reviewReference: "review-cc0",
        },
    },
    reviewedExpressions: [],
};
function writeCase(name, mutate = () => {}, policies = {}) {
    const directory = path.join(temp, name);
    fs.mkdirSync(directory);
    const fixture = {
        subject: structuredClone(subject),
        reports: Object.fromEntries(
            Object.entries(payloads).map(([type, payload]) => [
                type,
                makeReport(type, structuredClone(payload)),
            ])
        ),
    };
    mutate(fixture);
    fs.writeFileSync(
        path.join(directory, "subject.json"),
        JSON.stringify(fixture.subject)
    );
    for (const [type, report] of Object.entries(fixture.reports))
        fs.writeFileSync(
            path.join(directory, `${type}.json`),
            JSON.stringify(report)
        );
    const exceptionsPath = path.join(directory, "exceptions.json");
    const licensePath = path.join(directory, "licenses.json");
    fs.writeFileSync(
        exceptionsPath,
        JSON.stringify(
            policies.exceptions || { schemaVersion: 1, exceptions: [] }
        )
    );
    fs.writeFileSync(
        licensePath,
        JSON.stringify(policies.licenses || licensePolicy)
    );
    const result = spawnSync(
        process.execPath,
        [checker, "evaluate", directory],
        {
            encoding: "utf8",
            env: {
                ...process.env,
                VULNERABILITY_EXCEPTIONS_PATH: exceptionsPath,
                LICENSE_POLICY_PATH: licensePath,
            },
        }
    );
    return { directory, result };
}
const expectPass = (name, mutate, policies) => {
    const { result } = writeCase(name, mutate, policies);
    assert.equal(result.status, 0, `${name} should pass: ${result.stderr}`);
};
const expectFail = (name, mutate, policies) => {
    const { result } = writeCase(name, mutate, policies);
    assert.notEqual(result.status, 0, `${name} should fail`);
};
function addFinding(fixture, severity = "High", scope = "resolved-dependency") {
    fixture.reports[
        scope === "image"
            ? "image-vulnerabilities"
            : "dependency-vulnerabilities"
    ].payload.matches.push({
        id: "GHSA-fixture",
        severity,
        aliases: ["CVE-2026-0001"],
        component: "fixture-package",
        version: "1.0.0",
        locations: ["node_modules/fixture-package/package.json"],
    });
}
function validException(scope = "resolved-dependency") {
    return {
        id: `EX-${scope}`,
        findingId: "GHSA-fixture",
        aliases: ["CVE-2026-0001"],
        component: "fixture-package",
        version: "1.0.0",
        path: "node_modules/fixture-package/package.json",
        scope,
        severity: "high",
        subjectCommit: commit,
        imageDigest: scope === "image" ? imageDigest : null,
        owner: "owner",
        securityApprover: "security-owner",
        releaseOwnerApprover: null,
        reviewReference: "review-1",
        remediationTracker: "issue-1",
        riskRationale: "bounded fixture risk",
        compensatingControls: "fixture isolation",
        createdAt: new Date(now - 60_000).toISOString(),
        expiresAt: new Date(now + 86_400_000).toISOString(),
    };
}

function runRecord(name, type, raw, env = {}) {
    const directory = path.join(temp, `record-${name}`);
    fs.mkdirSync(directory);
    fs.writeFileSync(
        path.join(directory, "subject.json"),
        JSON.stringify(subject)
    );
    const rawPath = path.join(directory, "raw");
    fs.writeFileSync(rawPath, raw);
    const output = path.join(directory, "output.json");
    const contract = contracts[type];
    const result = spawnSync(
        process.execPath,
        [checker, "record", type, rawPath, output],
        {
            encoding: "utf8",
            env: {
                ...process.env,
                SCANNER_STARTED_AT: timestamp,
                SCANNER_COMPLETED_AT: timestamp,
                SCANNER_EXIT_CODE: "0",
                SCANNER_COMPLETE: "true",
                SCANNER_NAME: contract.name,
                SCANNER_VERSION: contract.version,
                SCANNER_IDENTITY: contract.identity,
                SCANNER_RULESET_DIGEST: contract.rulesetDigest || "",
                SCANNER_DATABASE_UPDATED_AT: contract.database
                    ? databaseTimestamp
                    : "",
                SCANNER_DATABASE_VALID: contract.database ? "true" : "",
                SCANNER_DATABASE_IDENTITY: contract.database
                    ? "v6.1.9|https://grype.example/database.tar.zst"
                    : "",
                SCANNER_INPUT_DIGEST: contract.inputDigest || "",
                ...env,
            },
        }
    );
    return { result, output };
}

try {
    expectPass("valid");
    expectPass("medium-visible", (fixture) => addFinding(fixture, "Medium"));
    expectFail("critical", (fixture) => addFinding(fixture, "Critical"));
    expectFail("high", (fixture) => addFinding(fixture));
    expectFail("unknown", (fixture) => addFinding(fixture, "mystery"));
    expectFail("verified-secret", (fixture) =>
        fixture.reports.secrets.payload.findings.push({
            detector: "fixture",
            status: "verified",
            source: { commit, file: "a", line: 1 },
        })
    );
    expectFail("malformed-secret-status", (fixture) =>
        fixture.reports.secrets.payload.findings.push({
            detector: "fixture",
            status: "typo",
            source: { commit, file: "a", line: 1 },
        })
    );
    expectFail("secret-raw-field", (fixture) =>
        fixture.reports.secrets.payload.findings.push({
            detector: "fixture",
            status: "unknown",
            source: { commit, file: "a", line: 1 },
            Raw: "must-not-survive",
        })
    );
    expectFail("scanner-failure", (fixture) => {
        fixture.reports.sast.complete = "true";
    });
    expectFail("bad-raw-digest", (fixture) => {
        fixture.reports.sast.rawDigest = "bad";
    });
    expectFail("wrong-subject-field", (fixture) => {
        fixture.reports.sast.subject.workflow.ref = "other";
    });
    expectFail("stale-report", (fixture) => {
        fixture.reports.sast.completedAt = new Date(
            now - 3 * 3600000
        ).toISOString();
    });
    expectFail("stale-db-at-evaluation", (fixture) => {
        fixture.reports[
            "dependency-vulnerabilities"
        ].scanner.databaseUpdatedAt = new Date(
            now - 25 * 3600000
        ).toISOString();
    });
    expectFail("invalid-db", (fixture) => {
        fixture.reports["image-vulnerabilities"].scanner.databaseValid = false;
    });
    expectFail("invalid-db-identity", (fixture) => {
        fixture.reports["dependency-vulnerabilities"].scanner.databaseIdentity =
            "unrelated";
    });
    expectFail("wrong-source-sbom-input", (fixture) => {
        fixture.reports["dependency-vulnerabilities"].scanner.inputDigest =
            `sha256:${"e".repeat(64)}`;
    });
    expectFail("wrong-image-input", (fixture) => {
        fixture.reports["image-vulnerabilities"].scanner.inputDigest =
            `sha256:${"e".repeat(64)}`;
    });
    expectFail("wrong-image-payload", (fixture) => {
        fixture.reports["image-vulnerabilities"].payload.target.imageID =
            `sha256:${"e".repeat(64)}`;
    });
    expectFail("wrong-image-sbom", (fixture) => {
        fixture.reports["image-sbom"].payload.packages[0].versionInfo =
            "not-the-image-digest";
    });
    expectFail("license-omission", (fixture) => {
        fixture.reports["license-inventory"].payload.components.pop();
    });
    expectFail("malformed-spdx", (fixture) => {
        fixture.reports[
            "license-inventory"
        ].payload.components[0].spdxExpression = "MIT AND (Apache-2.0";
    });
    expectFail("noassertion", (fixture) => {
        fixture.reports[
            "license-inventory"
        ].payload.components[0].spdxExpression = "NOASSERTION";
    });
    expectFail("unreviewed-with-exception", (fixture) => {
        fixture.reports[
            "license-inventory"
        ].payload.components[0].spdxExpression =
            "Apache-2.0 WITH LLVM-exception";
    });
    expectPass(
        "reviewed-with-exception",
        (fixture) => {
            fixture.reports[
                "license-inventory"
            ].payload.components[0].spdxExpression =
                "Apache-2.0 WITH LLVM-exception";
        },
        {
            licenses: {
                ...licensePolicy,
                allowedSpdx: [...licensePolicy.allowedSpdx, "Apache-2.0"],
                obligationEvidence: {
                    ...licensePolicy.obligationEvidence,
                    "Apache-2.0": {
                        obligationsComplete: true,
                        evidence: "fixture Apache notice",
                        reviewReference: "review-apache",
                    },
                },
                reviewedExpressions: [
                    {
                        expression: "Apache-2.0 WITH LLVM-exception",
                        selected: "Apache-2.0 WITH LLVM-exception",
                        owner: "owner",
                        approver: "legal",
                        reviewReference: "review",
                        obligationsComplete: true,
                        obligationEvidence: "fixture exception terms",
                    },
                ],
            },
        }
    );
    expectPass(
        "reviewed-or",
        (fixture) => {
            fixture.reports[
                "license-inventory"
            ].payload.components[0].spdxExpression = "(MIT OR CC0-1.0)";
        },
        {
            licenses: {
                ...licensePolicy,
                reviewedExpressions: [
                    {
                        expression: "(MIT OR CC0-1.0)",
                        selected: "MIT",
                        owner: "owner",
                        approver: "legal",
                        reviewReference: "review",
                        obligationsComplete: true,
                        obligationEvidence: "fixture OR selection",
                    },
                ],
            },
        }
    );
    expectFail(
        "unavailable-or-selection",
        (fixture) => {
            fixture.reports[
                "license-inventory"
            ].payload.components[0].spdxExpression =
                "(GPL-3.0-only OR AGPL-3.0-only)";
        },
        {
            licenses: {
                ...licensePolicy,
                reviewedExpressions: [
                    {
                        expression: "(GPL-3.0-only OR AGPL-3.0-only)",
                        selected: "MIT",
                        owner: "owner",
                        approver: "legal",
                        reviewReference: "review",
                        obligationsComplete: true,
                        obligationEvidence: "bad",
                    },
                ],
            },
        }
    );
    expectPass("valid-exception", (fixture) => addFinding(fixture), {
        exceptions: { schemaVersion: 1, exceptions: [validException()] },
    });
    expectPass(
        "valid-image-exception",
        (fixture) => addFinding(fixture, "High", "image"),
        {
            exceptions: {
                schemaVersion: 1,
                exceptions: [validException("image")],
            },
        }
    );
    expectFail("duplicate-exception-id", undefined, {
        exceptions: {
            schemaVersion: 1,
            exceptions: [validException(), validException()],
        },
    });
    expectFail("expired-unrelated-exception", undefined, {
        exceptions: {
            schemaVersion: 1,
            exceptions: [
                {
                    ...validException(),
                    expiresAt: new Date(now - 1).toISOString(),
                },
            ],
        },
    });
    expectFail("wildcard-unrelated-exception", undefined, {
        exceptions: {
            schemaVersion: 1,
            exceptions: [{ ...validException(), path: "node_modules/*" }],
        },
    });
    expectFail(
        "wrong-image-exception",
        (fixture) => addFinding(fixture, "High", "image"),
        {
            exceptions: {
                schemaVersion: 1,
                exceptions: [
                    {
                        ...validException("image"),
                        imageDigest: `sha256:${"f".repeat(64)}`,
                    },
                ],
            },
        }
    );
    expectFail("bad-policy-schema", undefined, {
        exceptions: { schemaVersion: 2, exceptions: [] },
    });

    const semgrepMarker = "SENSITIVE-MARKER";
    const semgrepRaw = JSON.stringify({
        results: [
            {
                check_id: "rule",
                path: "src/a.ts",
                start: { line: 1, col: 1 },
                end: { line: 1, col: 2 },
                extra: {
                    severity: "ERROR",
                    lines: semgrepMarker,
                    metavars: { X: { abstract_content: semgrepMarker } },
                },
            },
        ],
        errors: [],
    });
    const semgrepRecord = runRecord("semgrep", "sast", semgrepRaw);
    assert.equal(semgrepRecord.result.status, 0, semgrepRecord.result.stderr);
    assert.ok(
        !fs.readFileSync(semgrepRecord.output, "utf8").includes(semgrepMarker)
    );
    assert.notEqual(
        runRecord(
            "semgrep-errors",
            "sast",
            JSON.stringify({
                results: [],
                errors: [{ message: "parse failed" }],
            })
        ).result.status,
        0
    );
    assert.notEqual(
        runRecord("empty-grype", "dependency-vulnerabilities", "", {}).result
            .status,
        0
    );
    assert.notEqual(
        runRecord(
            "operational-grype",
            "dependency-vulnerabilities",
            JSON.stringify({ source: { target: {} }, matches: [] }),
            { SCANNER_EXIT_CODE: "1" }
        ).result.status,
        0
    );
    const grypeRaw = JSON.stringify({
        source: { target: { userInput: "sbom.json" } },
        matches: [
            {
                vulnerability: { id: "GHSA-fixture", severity: "High" },
                relatedVulnerabilities: [{ id: "CVE-2026-0001" }],
                artifact: {
                    name: "fixture",
                    version: "1.0.0",
                    locations: [{ path: "node_modules/fixture/package.json" }],
                },
            },
        ],
    });
    const grypeRecord = runRecord(
        "grype",
        "dependency-vulnerabilities",
        grypeRaw
    );
    assert.equal(grypeRecord.result.status, 0, grypeRecord.result.stderr);
    assert.deepEqual(
        JSON.parse(fs.readFileSync(grypeRecord.output)).payload.matches[0]
            .aliases,
        ["CVE-2026-0001"]
    );
    console.log("Security-policy record/evaluation and negative tests passed.");
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}
