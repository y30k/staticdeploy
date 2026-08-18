#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "m2-gate-"));
const securityDirectory = path.join(temporaryDirectory, "security");
fs.mkdirSync(securityDirectory);
const digest = (value) =>
    `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
const commit = execFileSync("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
}).trim();
const lockDigest = digest(fs.readFileSync("yarn.lock"));
const writeJson = (filePath, value) =>
    fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
try {
    const toolchainRoot = path.join(temporaryDirectory, "toolchain");
    const toolchainPath = path.join(
        toolchainRoot,
        "reports/toolchain-evidence.json"
    );
    const outputPath = path.join(temporaryDirectory, "gate.json");
    const coverageBytes = {
        backend: Buffer.from('{"backend":"coverage"}\n'),
        frontend: Buffer.from('{"frontend":"coverage"}\n'),
    };
    const coverage = {
        backend: {
            path: "coverage/coverage-final.json",
            digest: digest(coverageBytes.backend),
        },
        frontend: {
            path: "management-console/coverage/coverage-final.json",
            digest: digest(coverageBytes.frontend),
        },
    };
    for (const [name, item] of Object.entries(coverage)) {
        const coveragePath = path.join(toolchainRoot, item.path);
        fs.mkdirSync(path.dirname(coveragePath), { recursive: true });
        fs.writeFileSync(coveragePath, coverageBytes[name]);
    }
    const toolchain = {
        schemaVersion: 1,
        commit,
        lockDigest,
        nodeVersion: "24.19.0",
        yarnVersion: "4.18.0",
        workspaceCount: 13,
        typecheckProjectCount: 28,
        checks: [
            "compile",
            "format",
            "immutable-install",
            "install-policy",
            "install-script-inventory",
            "lint",
            "typecheck",
            "unit-integration-coverage",
        ].map((name) => ({ name, passed: true })),
        coverage,
        generatedAt: "2026-08-18T22:00:00.000Z",
    };
    fs.mkdirSync(path.dirname(toolchainPath), { recursive: true });
    writeJson(toolchainPath, toolchain);
    const subject = {
        schemaVersion: 1,
        commit,
        lockDigest,
        imageConfigDigest: `sha256:${"1".repeat(64)}`,
        imageManifestDigest: null,
        workflow: {
            repository: "y30k/staticdeploy",
            runId: "fixture",
            runAttempt: "1",
            eventName: "pull_request",
            ref: "refs/pull/fixture/merge",
        },
    };
    const subjectPath = path.join(securityDirectory, "subject.json");
    const vulnerabilityPath = path.join(
        securityDirectory,
        "vulnerability-evaluation.json"
    );
    const licensePath = path.join(securityDirectory, "license-evaluation.json");
    const vulnerability = {
        schemaVersion: 1,
        subject: structuredClone(subject),
        evaluatedAt: "2026-08-18T22:00:00.000Z",
        passed: true,
        blockingFindingCount: 0,
        advisoryFindingCount: 2,
        secretFindingCount: 0,
    };
    const retainedEvidencePath = "docs/security/license-evidence/fixture.txt";
    const retainedEvidenceBytes = "retained evidence\n";
    const licenses = {
        schemaVersion: 1,
        subject: structuredClone(subject),
        evaluatedAt: "2026-08-18T22:00:00.000Z",
        passed: true,
        prohibitedCount: 0,
        approvedInventory: {
            path: retainedEvidencePath,
            digest: digest(retainedEvidenceBytes),
        },
        evidenceArtifacts: [
            {
                path: retainedEvidencePath,
                digest: digest(retainedEvidenceBytes),
            },
        ],
        components: [{ component: "fixture", allowed: true }],
    };
    writeJson(subjectPath, subject);
    writeJson(vulnerabilityPath, vulnerability);
    writeJson(licensePath, licenses);
    const images = [];
    for (const [index, architecture] of ["amd64", "arm64"].entries()) {
        const configDigest = `sha256:${String(index + 1).repeat(64)}`;
        const conformancePath = `image-conformance-${architecture}.json`;
        const conformanceBytes = `${JSON.stringify(
            {
                schemaVersion: 1,
                platform: `linux/${architecture}`,
                configDigest,
                passed: true,
            },
            null,
            2
        )}\n`;
        fs.writeFileSync(
            path.join(securityDirectory, conformancePath),
            conformanceBytes
        );
        images.push({
            platform: `linux/${architecture}`,
            image: `fixture:${architecture}`,
            configDigest,
            manifestDigest: `sha256:${String(index + 3).repeat(64)}`,
            layerDigests: [`sha256:${String(index + 5).repeat(64)}`],
            sizeBytes: 160_000_000 + index,
            revision: commit,
            user: "65532:65532",
            entrypoint: ["/nodejs/bin/node"],
            command: ["build/server.js"],
            repoDigests: [],
            conformance: {
                path: conformancePath,
                digest: digest(conformanceBytes),
                passed: true,
            },
        });
    }
    writeJson(path.join(securityDirectory, "multiarch-images.json"), {
        schemaVersion: 1,
        commit,
        lockDigest,
        generatedAt: "2026-08-18T22:00:00.000Z",
        registryNegative: true,
        images,
    });
    const inventoryComponents = [
        ["component", "1.0.0", "pkg:npm/component@1.0.0", "MIT"],
    ];
    writeJson(path.join(securityDirectory, "multiarch-inventory.json"), {
        schemaVersion: 1,
        commit,
        equivalent: true,
        componentCount: inventoryComponents.length,
        normalizedInventoryDigest: digest(
            Buffer.from(
                `${inventoryComponents
                    .map((component) => JSON.stringify(component))
                    .join("\n")}\n`
            )
        ),
        components: inventoryComponents,
        images: images.map((image, index) => ({
            platform: image.platform,
            configDigest: image.configDigest,
            spdxDigest: `sha256:${String(index + 7).repeat(64)}`,
        })),
    });
    for (const name of [
        "dependency-vulnerabilities.json",
        "image-sbom.json",
        "image-vulnerabilities.json",
        "license-inventory.json",
        "normalized-findings.json",
        "normalized-license-inventory.json",
        "sast.json",
        "secrets.json",
        "source-sbom.json",
    ])
        writeJson(path.join(securityDirectory, name), {});
    const retainedLicensePath = path.join(
        securityDirectory,
        retainedEvidencePath
    );
    fs.mkdirSync(path.dirname(retainedLicensePath), { recursive: true });
    fs.writeFileSync(retainedLicensePath, retainedEvidenceBytes);
    const run = (expectedStatus) => {
        const result = spawnSync(
            process.execPath,
            [
                "scripts/verify-m2-gate.mjs",
                toolchainPath,
                securityDirectory,
                outputPath,
            ],
            { encoding: "utf8" }
        );
        assert.equal(result.status, expectedStatus, result.stderr);
    };
    run(0);
    const manifest = JSON.parse(fs.readFileSync(outputPath, "utf8"));
    assert.equal(manifest.passed, true);
    assert.equal(manifest.commit, commit);
    assert.equal(manifest.images.length, 2);
    assert.equal(
        manifest.evidence.security[retainedEvidencePath],
        digest(retainedEvidenceBytes)
    );
    const gateWrapper = fs.readFileSync(
        "scripts/gates/m2-toolchain.sh",
        "utf8"
    );
    for (const generated of [
        "normalized-findings.json",
        "vulnerability-evaluation.json",
        "normalized-license-inventory.json",
        "license-evaluation.json",
    ])
        assert.ok(gateWrapper.includes(`"$2/${generated}"`));
    assert.ok(
        gateWrapper.indexOf("rm -f") <
            gateWrapper.indexOf('security-policy.mjs evaluate "$2"') &&
            gateWrapper.indexOf('security-policy.mjs evaluate "$2"') <
                gateWrapper.indexOf('verify-m2-gate.mjs "$1" "$2" "$3"')
    );

    const invalidToolchain = structuredClone(toolchain);
    invalidToolchain.checks[0].name = "unapproved-check";
    writeJson(toolchainPath, invalidToolchain);
    run(1);
    writeJson(toolchainPath, toolchain);

    fs.writeFileSync(
        path.join(toolchainRoot, coverage.backend.path),
        "tampered coverage"
    );
    run(1);
    fs.writeFileSync(
        path.join(toolchainRoot, coverage.backend.path),
        coverageBytes.backend
    );

    const mismatchedSubject = {
        ...subject,
        imageConfigDigest: `sha256:${"9".repeat(64)}`,
    };
    writeJson(subjectPath, mismatchedSubject);
    writeJson(vulnerabilityPath, {
        ...vulnerability,
        subject: mismatchedSubject,
    });
    writeJson(licensePath, { ...licenses, subject: mismatchedSubject });
    run(1);
    writeJson(subjectPath, subject);
    writeJson(vulnerabilityPath, vulnerability);
    writeJson(licensePath, licenses);

    vulnerability.subject.commit = "f".repeat(40);
    writeJson(vulnerabilityPath, vulnerability);
    run(1);
    vulnerability.subject.commit = commit;
    writeJson(vulnerabilityPath, vulnerability);

    fs.writeFileSync(path.join(securityDirectory, "scanner.raw.json"), "{}");
    run(1);
    fs.rmSync(path.join(securityDirectory, "scanner.raw.json"));

    const specialPath = path.join(securityDirectory, "special-link");
    fs.symlinkSync(subjectPath, specialPath);
    run(1);
    fs.rmSync(specialPath);
    console.log("M2 gate manifest and fail-closed fixture tests passed.");
} finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
}
