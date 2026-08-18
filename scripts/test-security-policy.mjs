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
const lockDigest = `sha256:${createHash("sha256").update(fs.readFileSync("yarn.lock")).digest("hex")}`;
const imageDigest = `sha256:${"a".repeat(64)}`;
const now = Date.now();
const timestamp = new Date(now - 60_000).toISOString();
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
const scanner = {
    name: "fixture",
    version: "1.0.0",
    identity: "fixture@sha256:abc",
    rulesetDigest: "sha256:rules",
    databaseUpdatedAt: new Date(now - 2 * 60 * 60 * 1000).toISOString(),
};
const payloads = {
    "dependency-vulnerabilities": { advisories: [] },
    sast: { results: [] },
    secrets: { findings: [] },
    "image-vulnerabilities": {
        source: { target: { imageID: imageDigest } },
        matches: [],
    },
    "source-sbom": {
        bomFormat: "CycloneDX",
        components: [{ name: "fixture" }],
    },
    "image-sbom": {
        spdxVersion: "SPDX-2.3",
        packages: [
            {
                name: "fixture-image",
                SPDXID: "SPDXRef-fixture-image",
                versionInfo: "1.0.0",
                licenseDeclared: "MIT",
                licenseConcluded: "MIT",
            },
        ],
    },
    "license-inventory": {
        components: [
            {
                component: "fixture",
                locator: "fixture@npm:1.0.0",
                version: "1.0.0",
                scope: "resolved",
                spdxExpression: "MIT",
            },
        ],
    },
};

function makeReport(type, payload, overrides = {}) {
    return {
        schemaVersion: 1,
        type,
        subject,
        scanner: structuredClone(scanner),
        startedAt: timestamp,
        completedAt: timestamp,
        exitCode: 0,
        acceptedExitCodes: [0],
        complete: true,
        rawDigest: `sha256:${"b".repeat(64)}`,
        payload,
        ...overrides,
    };
}
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
        JSON.stringify(
            policies.licenses || {
                schemaVersion: 1,
                allowedSpdx: ["MIT"],
                reviewedExpressions: [],
            }
        )
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
const addDependencyFinding = (fixture, severity = "high") => {
    fixture.reports["dependency-vulnerabilities"].payload.advisories.push({
        value: "fixture-package",
        children: {
            ID: "GHSA-fixture",
            Severity: severity,
            "Tree Versions": ["1.0.0"],
            Dependents: ["fixture-root"],
        },
    });
};

try {
    expectPass("valid");
    expectPass("medium-visible", (fixture) =>
        addDependencyFinding(fixture, "moderate")
    );
    expectFail("critical", (fixture) =>
        addDependencyFinding(fixture, "critical")
    );
    expectFail("high", (fixture) => addDependencyFinding(fixture, "high"));
    expectFail("unknown", (fixture) =>
        addDependencyFinding(fixture, "mystery")
    );
    expectFail("verified-secret", (fixture) =>
        fixture.reports.secrets.payload.findings.push({ status: "verified" })
    );
    expectFail("unknown-secret", (fixture) =>
        fixture.reports.secrets.payload.findings.push({ status: "unknown" })
    );
    expectFail("scanner-failure", (fixture) => {
        fixture.reports.sast.complete = false;
        fixture.reports.sast.exitCode = 2;
    });
    expectFail("stale-report", (fixture) => {
        fixture.reports.sast.completedAt = new Date(
            now - 3 * 60 * 60 * 1000
        ).toISOString();
    });
    expectFail("stale-database", (fixture) => {
        fixture.reports["image-vulnerabilities"].scanner.databaseUpdatedAt =
            new Date(now - 25 * 60 * 60 * 1000).toISOString();
    });
    expectFail("wrong-commit", (fixture) => {
        fixture.reports.sast.subject = { ...subject, commit: "f".repeat(40) };
    });
    expectFail("wrong-image", (fixture) => {
        fixture.reports["image-vulnerabilities"].payload.source.target.imageID =
            `sha256:${"f".repeat(64)}`;
    });
    expectFail("malformed-sbom", (fixture) => {
        fixture.reports["source-sbom"].payload = { components: [] };
    });
    expectFail("tag-spoof", (fixture) => {
        fixture.subject.workflow.ref = "refs/tags/untrusted";
    });
    expectFail("untrusted-fork-event", (fixture) => {
        fixture.subject.workflow.eventName = "pull_request_target";
    });
    expectFail("unknown-license", (fixture) => {
        fixture.reports[
            "license-inventory"
        ].payload.components[0].spdxExpression = "NOASSERTION";
    });
    expectFail("prohibited-license", (fixture) => {
        fixture.reports[
            "license-inventory"
        ].payload.components[0].spdxExpression = "GPL-3.0-only";
    });
    expectPass(
        "completed-license-obligation",
        (fixture) => {
            fixture.reports[
                "license-inventory"
            ].payload.components[0].spdxExpression = "(MIT OR CC0-1.0)";
        },
        {
            licenses: {
                schemaVersion: 1,
                allowedSpdx: ["MIT", "CC0-1.0"],
                reviewedExpressions: [
                    {
                        expression: "(MIT OR CC0-1.0)",
                        selected: "MIT",
                        owner: "security-owner",
                        approver: "legal-owner",
                        reviewReference: "review-1",
                        obligationsComplete: true,
                    },
                ],
            },
        }
    );
    const exception = {
        id: "EX-1",
        findingId: "GHSA-fixture",
        aliases: [],
        component: "fixture-package",
        version: "1.0.0",
        path: "fixture-root",
        scope: "resolved-dependency",
        severity: "high",
        subjectCommit: commit,
        owner: "owner",
        securityApprover: "security-owner",
        reviewReference: "review-1",
        remediationTracker: "issue-1",
        riskRationale: "bounded fixture risk",
        compensatingControls: "fixture isolation",
        createdAt: new Date(now - 60_000).toISOString(),
        expiresAt: new Date(now + 24 * 60 * 60 * 1000).toISOString(),
    };
    expectPass("valid-exception", (fixture) => addDependencyFinding(fixture), {
        exceptions: { schemaVersion: 1, exceptions: [exception] },
    });
    expectFail(
        "unapproved-exception",
        (fixture) => addDependencyFinding(fixture),
        {
            exceptions: {
                schemaVersion: 1,
                exceptions: [{ ...exception, securityApprover: "" }],
            },
        }
    );
    expectFail(
        "expired-exception",
        (fixture) => addDependencyFinding(fixture),
        {
            exceptions: {
                schemaVersion: 1,
                exceptions: [
                    {
                        ...exception,
                        createdAt: new Date(
                            now - 2 * 24 * 60 * 60 * 1000
                        ).toISOString(),
                        expiresAt: new Date(now - 60_000).toISOString(),
                    },
                ],
            },
        }
    );
    expectFail(
        "wrong-subject-exception",
        (fixture) => addDependencyFinding(fixture),
        {
            exceptions: {
                schemaVersion: 1,
                exceptions: [{ ...exception, subjectCommit: "f".repeat(40) }],
            },
        }
    );
    expectFail(
        "wildcard-exception",
        (fixture) => addDependencyFinding(fixture),
        {
            exceptions: {
                schemaVersion: 1,
                exceptions: [{ ...exception, path: "*" }],
            },
        }
    );
    console.log("Security-policy fixture and negative tests passed.");
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}
