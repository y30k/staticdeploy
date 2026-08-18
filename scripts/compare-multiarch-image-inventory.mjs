#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const [outputPath, amd64Path, arm64Path, amd64Digest, arm64Digest] =
    process.argv.slice(2);
if (
    !outputPath ||
    !amd64Path ||
    !arm64Path ||
    !/^sha256:[a-f0-9]{64}$/.test(amd64Digest || "") ||
    !/^sha256:[a-f0-9]{64}$/.test(arm64Digest || "") ||
    amd64Digest === arm64Digest
)
    throw new Error(
        "usage: compare-multiarch-image-inventory.mjs OUTPUT AMD64_SPDX ARM64_SPDX AMD64_CONFIG_DIGEST ARM64_CONFIG_DIGEST"
    );
const digest = (value) =>
    `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
const normalizedPurl = (purl) => {
    assert.match(purl, /^pkg:/, "image component must have a package URL");
    const [base, query = ""] = purl.split("?", 2);
    const parameters = new URLSearchParams(query);
    parameters.delete("arch");
    parameters.sort();
    const normalizedQuery = parameters.toString();
    return normalizedQuery ? `${base}?${normalizedQuery}` : base;
};
const inventory = (filePath, expectedPlatform, expectedConfigDigest) => {
    const raw = fs.readFileSync(filePath);
    const spdx = JSON.parse(raw);
    assert.equal(spdx.spdxVersion, "SPDX-2.3");
    assert.ok(Array.isArray(spdx.relationships));
    assert.ok(Array.isArray(spdx.packages));
    const roots = new Set(
        spdx.relationships
            .filter(
                (relationship) =>
                    relationship.spdxElementId === "SPDXRef-DOCUMENT" &&
                    relationship.relationshipType === "DESCRIBES"
            )
            .map((relationship) => relationship.relatedSpdxElement)
    );
    assert.equal(
        roots.size,
        1,
        "SPDX document must describe exactly one image"
    );
    const root = spdx.packages.find((component) => roots.has(component.SPDXID));
    assert.ok(root, "SPDX document root package is missing");
    assert.equal(
        root.versionInfo,
        expectedConfigDigest.slice("sha256:".length),
        "SPDX root must identify the exact image configuration"
    );
    const rootPurl = root.externalRefs?.find(
        (reference) => reference.referenceType === "purl"
    )?.referenceLocator;
    assert.ok(rootPurl?.startsWith("pkg:oci/"));
    const rootParameters = new URLSearchParams(rootPurl.split("?", 2)[1] || "");
    assert.equal(rootParameters.get("arch"), expectedPlatform.split("/")[1]);
    assert.equal(
        rootParameters.get("tag"),
        expectedConfigDigest.slice("sha256:".length)
    );
    const ids = spdx.packages.map((component) => component.SPDXID);
    assert.equal(
        new Set(ids).size,
        ids.length,
        "SPDX package IDs must be unique"
    );
    const components = spdx.packages
        .filter((component) => !roots.has(component.SPDXID))
        .map((component) => {
            const purl = component.externalRefs?.find(
                (reference) => reference.referenceType === "purl"
            )?.referenceLocator;
            const license =
                component.licenseConcluded &&
                component.licenseConcluded !== "NOASSERTION"
                    ? component.licenseConcluded
                    : component.licenseDeclared || "NOASSERTION";
            assert.ok(
                component.name && component.versionInfo && purl && license
            );
            return JSON.stringify([
                component.name,
                component.versionInfo,
                normalizedPurl(purl),
                license,
            ]);
        })
        .sort();
    assert.ok(components.length, "image inventory must not be empty");
    return { rawDigest: digest(raw), components };
};
const amd64 = inventory(amd64Path, "linux/amd64", amd64Digest);
const arm64 = inventory(arm64Path, "linux/arm64", arm64Digest);
assert.deepEqual(
    arm64.components,
    amd64.components,
    "arm64 component/version/license inventory must equal amd64 after architecture normalization"
);
const commit = execFileSync("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
}).trim();
if (process.env.GITHUB_SHA) assert.equal(commit, process.env.GITHUB_SHA);
const normalizedInventoryDigest = digest(
    Buffer.from(`${amd64.components.join("\n")}\n`)
);
const report = {
    schemaVersion: 1,
    commit,
    equivalent: true,
    componentCount: amd64.components.length,
    normalizedInventoryDigest,
    components: amd64.components.map((component) => JSON.parse(component)),
    images: [
        {
            platform: "linux/amd64",
            configDigest: amd64Digest,
            spdxDigest: amd64.rawDigest,
        },
        {
            platform: "linux/arm64",
            configDigest: arm64Digest,
            spdxDigest: arm64.rawDigest,
        },
    ],
};
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, {
    mode: 0o600,
});
console.log(
    `Verified ${report.componentCount} normalized image components across amd64 and arm64.`
);
