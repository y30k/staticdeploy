#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const [toolchainPath, securityDirectory, outputPath] = process.argv.slice(2);
if (!toolchainPath || !securityDirectory || !outputPath)
    throw new Error(
        "usage: verify-m2-gate.mjs TOOLCHAIN_EVIDENCE SECURITY_EVIDENCE_DIRECTORY OUTPUT"
    );
const read = (filePath) => JSON.parse(fs.readFileSync(filePath, "utf8"));
const exactKeys = (value, expected, name) =>
    assert.deepEqual(
        Object.keys(value).sort(),
        [...expected].sort(),
        `${name} has unexpected or missing fields`
    );
const digestValue = (value) =>
    `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
const digestFile = (filePath) => digestValue(fs.readFileSync(filePath));
const evidencePath = (name) => path.join(securityDirectory, name);
const checkoutCommit = execFileSync("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
}).trim();
if (process.env.GITHUB_SHA)
    assert.equal(checkoutCommit, process.env.GITHUB_SHA);
const checkoutLockDigest = digestFile("yarn.lock");
const toolchain = read(toolchainPath);
const subject = read(evidencePath("subject.json"));
const vulnerability = read(evidencePath("vulnerability-evaluation.json"));
const licenses = read(evidencePath("license-evaluation.json"));
const multiarch = read(evidencePath("multiarch-images.json"));
const inventory = read(evidencePath("multiarch-inventory.json"));
exactKeys(
    toolchain,
    [
        "schemaVersion",
        "commit",
        "lockDigest",
        "nodeVersion",
        "yarnVersion",
        "workspaceCount",
        "typecheckProjectCount",
        "checks",
        "coverage",
        "generatedAt",
    ],
    "toolchain evidence"
);
assert.equal(toolchain.schemaVersion, 1);
exactKeys(
    subject,
    [
        "schemaVersion",
        "commit",
        "lockDigest",
        "imageConfigDigest",
        "imageManifestDigest",
        "workflow",
    ],
    "policy subject"
);
assert.equal(subject.schemaVersion, 1);
exactKeys(
    subject.workflow,
    ["repository", "runId", "runAttempt", "eventName", "ref"],
    "policy workflow identity"
);
assert.match(subject.imageConfigDigest, /^sha256:[a-f0-9]{64}$/);
assert.equal(subject.imageManifestDigest, null);
exactKeys(
    vulnerability,
    [
        "schemaVersion",
        "subject",
        "evaluatedAt",
        "passed",
        "blockingFindingCount",
        "advisoryFindingCount",
        "secretFindingCount",
    ],
    "vulnerability evaluation"
);
assert.equal(vulnerability.schemaVersion, 1);
assert.ok(Number.isFinite(Date.parse(vulnerability.evaluatedAt)));
for (const field of [
    "blockingFindingCount",
    "advisoryFindingCount",
    "secretFindingCount",
])
    assert.ok(
        Number.isSafeInteger(vulnerability[field]) && vulnerability[field] >= 0
    );
exactKeys(
    licenses,
    [
        "schemaVersion",
        "subject",
        "evaluatedAt",
        "passed",
        "prohibitedCount",
        "approvedInventory",
        "evidenceArtifacts",
        "components",
    ],
    "license evaluation"
);
assert.equal(licenses.schemaVersion, 1);
assert.ok(Number.isFinite(Date.parse(licenses.evaluatedAt)));
assert.ok(
    Number.isSafeInteger(licenses.prohibitedCount) &&
        licenses.prohibitedCount >= 0
);
assert.ok(Array.isArray(licenses.components) && licenses.components.length > 0);
exactKeys(
    multiarch,
    [
        "schemaVersion",
        "commit",
        "lockDigest",
        "generatedAt",
        "registryNegative",
        "images",
    ],
    "multiarch image evidence"
);
assert.equal(multiarch.schemaVersion, 1);
exactKeys(
    inventory,
    [
        "schemaVersion",
        "commit",
        "equivalent",
        "componentCount",
        "normalizedInventoryDigest",
        "components",
        "images",
    ],
    "multiarch inventory evidence"
);
assert.equal(inventory.schemaVersion, 1);
const commits = new Set([
    toolchain.commit,
    subject.commit,
    vulnerability.subject.commit,
    licenses.subject.commit,
    multiarch.commit,
    inventory.commit,
]);
assert.equal(commits.size, 1, "all M2 gate evidence must identify one commit");
const [commit] = commits;
assert.match(commit, /^[a-f0-9]{40}$/);
assert.equal(
    commit,
    checkoutCommit,
    "gate evidence must identify checked-out HEAD"
);
assert.equal(subject.lockDigest, checkoutLockDigest);
assert.equal(toolchain.lockDigest, subject.lockDigest);
assert.equal(multiarch.lockDigest, subject.lockDigest);
assert.equal(toolchain.nodeVersion, "24.19.0");
assert.equal(toolchain.yarnVersion, "4.18.0");
assert.equal(toolchain.workspaceCount, 13);
assert.equal(toolchain.typecheckProjectCount, 28);
const expectedChecks = [
    "compile",
    "format",
    "immutable-install",
    "install-policy",
    "install-script-inventory",
    "lint",
    "typecheck",
    "unit-integration-coverage",
];
assert.deepEqual(
    toolchain.checks.map((check) => check.name).sort(),
    expectedChecks
);
for (const check of toolchain.checks) {
    exactKeys(check, ["name", "passed"], "toolchain check");
    assert.equal(check.passed, true);
}
assert.deepEqual(Object.keys(toolchain.coverage).sort(), [
    "backend",
    "frontend",
]);
assert.equal(toolchain.coverage.backend.path, "coverage/coverage-final.json");
assert.equal(
    toolchain.coverage.frontend.path,
    "management-console/coverage/coverage-final.json"
);
const toolchainArtifactRoot = path.resolve(path.dirname(toolchainPath), "..");
for (const coverage of Object.values(toolchain.coverage)) {
    exactKeys(coverage, ["path", "digest"], "coverage evidence");
    assert.match(coverage.digest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(path.normalize(coverage.path), coverage.path);
    assert.ok(
        !path.isAbsolute(coverage.path) && !coverage.path.startsWith("..")
    );
    const resolvedCoveragePath = path.resolve(
        toolchainArtifactRoot,
        coverage.path
    );
    assert.ok(
        resolvedCoveragePath.startsWith(`${toolchainArtifactRoot}${path.sep}`)
    );
    assert.equal(digestFile(resolvedCoveragePath), coverage.digest);
}
assert.deepEqual(vulnerability.subject, subject);
assert.deepEqual(licenses.subject, subject);
assert.equal(vulnerability.passed, true);
assert.equal(vulnerability.blockingFindingCount, 0);
assert.equal(vulnerability.secretFindingCount, 0);
assert.equal(licenses.passed, true);
assert.equal(licenses.prohibitedCount, 0);
assert.equal(multiarch.registryNegative, true);
assert.deepEqual(multiarch.images.map((image) => image.platform).sort(), [
    "linux/amd64",
    "linux/arm64",
]);
const amd64Image = multiarch.images.find(
    (image) => image.platform === "linux/amd64"
);
assert.equal(
    subject.imageConfigDigest,
    amd64Image.configDigest,
    "policy subject must be the conformed amd64 image"
);
assert.equal(
    new Set(multiarch.images.map((image) => image.configDigest)).size,
    2
);
assert.equal(
    new Set(multiarch.images.map((image) => image.manifestDigest)).size,
    2
);
for (const image of multiarch.images) {
    exactKeys(
        image,
        [
            "platform",
            "image",
            "configDigest",
            "manifestDigest",
            "layerDigests",
            "sizeBytes",
            "revision",
            "user",
            "entrypoint",
            "command",
            "repoDigests",
            "conformance",
        ],
        `${image.platform} image evidence`
    );
    assert.equal(image.revision, commit);
    assert.match(image.configDigest, /^sha256:[a-f0-9]{64}$/);
    assert.match(image.manifestDigest, /^sha256:[a-f0-9]{64}$/);
    assert.ok(Number.isSafeInteger(image.sizeBytes) && image.sizeBytes > 0);
    assert.equal(image.user, "65532:65532");
    assert.deepEqual(image.entrypoint, ["/nodejs/bin/node"]);
    assert.deepEqual(image.command, ["build/server.js"]);
    assert.ok(image.layerDigests.length > 0);
    assert.equal(new Set(image.layerDigests).size, image.layerDigests.length);
    for (const layerDigest of image.layerDigests)
        assert.match(layerDigest, /^sha256:[a-f0-9]{64}$/);
    assert.deepEqual(image.repoDigests, []);
    exactKeys(
        image.conformance,
        ["path", "digest", "passed"],
        `${image.platform} conformance reference`
    );
    assert.equal(image.conformance.passed, true);
    assert.equal(
        image.conformance.path,
        `image-conformance-${image.platform.slice("linux/".length)}.json`
    );
    const conformance = read(evidencePath(image.conformance.path));
    assert.deepEqual(conformance, {
        schemaVersion: 1,
        platform: image.platform,
        configDigest: image.configDigest,
        passed: true,
    });
    assert.equal(
        digestFile(evidencePath(image.conformance.path)),
        image.conformance.digest
    );
}
assert.equal(inventory.equivalent, true);
assert.equal(inventory.componentCount, inventory.components.length);
assert.ok(inventory.componentCount > 0);
for (const component of inventory.components) {
    assert.equal(component.length, 4);
    assert.ok(component.every((value) => typeof value === "string" && value));
    assert.match(component[2], /^pkg:/);
}
assert.equal(
    inventory.normalizedInventoryDigest,
    digestValue(
        Buffer.from(
            `${inventory.components
                .map((component) => JSON.stringify(component))
                .join("\n")}\n`
        )
    )
);
assert.equal(inventory.images.length, 2);
assert.equal(new Set(inventory.images.map((image) => image.platform)).size, 2);
for (const image of inventory.images) {
    exactKeys(
        image,
        ["platform", "configDigest", "spdxDigest"],
        "inventory image evidence"
    );
    assert.match(image.spdxDigest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(
        image.configDigest,
        multiarch.images.find(
            (candidate) => candidate.platform === image.platform
        )?.configDigest,
        `inventory ${image.platform} digest must match conformed image`
    );
}
const expectedTopLevelFiles = [
    "dependency-vulnerabilities.json",
    "image-conformance-amd64.json",
    "image-conformance-arm64.json",
    "image-sbom.json",
    "image-vulnerabilities.json",
    "license-evaluation.json",
    "license-inventory.json",
    "multiarch-images.json",
    "multiarch-inventory.json",
    "normalized-findings.json",
    "normalized-license-inventory.json",
    "sast.json",
    "secrets.json",
    "source-sbom.json",
    "subject.json",
    "vulnerability-evaluation.json",
].sort();
const topLevelEntries = fs.readdirSync(securityDirectory, {
    withFileTypes: true,
});
assert.ok(
    topLevelEntries.every((entry) => entry.isFile() || entry.isDirectory()),
    "security evidence cannot contain symlinks or special entries"
);
assert.deepEqual(
    topLevelEntries
        .filter((entry) => entry.isFile())
        .map((entry) => entry.name)
        .sort(),
    expectedTopLevelFiles,
    "security evidence top-level allowlist must be exact"
);
assert.deepEqual(
    topLevelEntries
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .sort(),
    ["docs"],
    "only retained license evidence may be nested"
);
const allEvidenceFiles = [];
const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        assert.ok(
            entry.isFile() || entry.isDirectory(),
            `special evidence entry is forbidden: ${entry.name}`
        );
        const entryPath = path.join(directory, entry.name);
        if (entry.isDirectory()) visit(entryPath);
        else allEvidenceFiles.push(path.relative(securityDirectory, entryPath));
    }
};
visit(securityDirectory);
assert.deepEqual(
    allEvidenceFiles.filter((file) => file.includes(".raw.")),
    [],
    "gate input must contain no raw scanner output"
);
const retainedLicensePaths = [];
for (const artifact of licenses.evidenceArtifacts) {
    exactKeys(artifact, ["path", "digest"], "retained license evidence");
    assert.ok(artifact.path.startsWith("docs/security/license-evidence/"));
    assert.equal(path.normalize(artifact.path), artifact.path);
    assert.match(artifact.digest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(digestFile(evidencePath(artifact.path)), artifact.digest);
    retainedLicensePaths.push(artifact.path);
}
assert.deepEqual(
    allEvidenceFiles.filter((file) => file.startsWith("docs/")).sort(),
    retainedLicensePaths.sort(),
    "nested evidence must exactly match the evaluated license artifact manifest"
);
const gateManifest = {
    schemaVersion: 1,
    commit,
    lockDigest: subject.lockDigest,
    passed: true,
    toolchain: {
        nodeVersion: toolchain.nodeVersion,
        yarnVersion: toolchain.yarnVersion,
        workspaceCount: toolchain.workspaceCount,
        typecheckProjectCount: toolchain.typecheckProjectCount,
        checks: toolchain.checks,
        coverage: toolchain.coverage,
        evidenceDigest: digestFile(toolchainPath),
    },
    policy: {
        vulnerabilityPassed: vulnerability.passed,
        blockingFindingCount: vulnerability.blockingFindingCount,
        advisoryFindingCount: vulnerability.advisoryFindingCount,
        secretFindingCount: vulnerability.secretFindingCount,
        licensePassed: licenses.passed,
        prohibitedLicenseCount: licenses.prohibitedCount,
    },
    evidence: {
        toolchain: digestFile(toolchainPath),
        security: Object.fromEntries(
            allEvidenceFiles
                .sort()
                .map((name) => [name, digestFile(evidencePath(name))])
        ),
    },
    images: multiarch.images.map((image) => ({
        platform: image.platform,
        configDigest: image.configDigest,
        manifestDigest: image.manifestDigest,
        layerDigests: image.layerDigests,
        conformanceDigest: image.conformance.digest,
    })),
    imageInventory: {
        equivalent: inventory.equivalent,
        componentCount: inventory.componentCount,
        normalizedDigest: inventory.normalizedInventoryDigest,
        images: inventory.images,
    },
    registryNegative: multiarch.registryNegative,
    generatedAt: new Date().toISOString(),
};
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(gateManifest, null, 2)}\n`, {
    mode: 0o600,
});
console.log(`M2 toolchain gate passed for ${commit}.`);
