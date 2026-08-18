#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const checker = path.resolve("scripts/compare-multiarch-image-inventory.mjs");
const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "multiarch-inventory-")
);
try {
    const source = JSON.parse(
        fs
            .readFileSync(
                "scripts/test-fixtures/security/syft-image-spdx.json",
                "utf8"
            )
            .replaceAll("CONFIG_DIGEST_HEX", "a".repeat(64))
            .replaceAll("MANIFEST_DIGEST_HEX", "b".repeat(64))
    );
    const packageComponent = source.packages.find(
        (component) => component.name === "fixture-package"
    );
    packageComponent.externalRefs[0].referenceLocator =
        "pkg:npm/fixture-package@1.0.0?arch=amd64&distro=fixture";
    const amd64Path = path.join(temporaryDirectory, "amd64.json");
    const arm64Path = path.join(temporaryDirectory, "arm64.json");
    const outputPath = path.join(temporaryDirectory, "evidence.json");
    const run = (arm64, expectedStatus) => {
        fs.writeFileSync(amd64Path, JSON.stringify(source));
        fs.writeFileSync(arm64Path, JSON.stringify(arm64));
        const result = spawnSync(
            process.execPath,
            [
                checker,
                outputPath,
                amd64Path,
                arm64Path,
                `sha256:${"a".repeat(64)}`,
                `sha256:${"d".repeat(64)}`,
            ],
            { encoding: "utf8" }
        );
        assert.equal(result.status, expectedStatus, result.stderr);
    };

    const equivalentArm64 = structuredClone(source);
    equivalentArm64.packages.find(
        (component) => component.name === "fixture-package"
    ).externalRefs[0].referenceLocator =
        "pkg:npm/fixture-package@1.0.0?distro=fixture&arch=arm64";
    const arm64Root = equivalentArm64.packages.find(
        (component) => component.SPDXID === "SPDXRef-DocumentRoot-Image-sha256"
    );
    arm64Root.versionInfo = "d".repeat(64);
    arm64Root.externalRefs[0].referenceLocator = `pkg:oci/sha256@sha256%3A${"b".repeat(64)}?arch=arm64&tag=${"d".repeat(64)}`;
    run(equivalentArm64, 0);
    const evidence = JSON.parse(fs.readFileSync(outputPath, "utf8"));
    assert.equal(evidence.equivalent, true);
    assert.equal(evidence.componentCount, 1);
    assert.deepEqual(evidence.components, [
        [
            "fixture-package",
            "1.0.0",
            "pkg:npm/fixture-package@1.0.0?distro=fixture",
            "MIT",
        ],
    ]);
    assert.match(evidence.normalizedInventoryDigest, /^sha256:[a-f0-9]{64}$/);

    run(source, 1);
    const rootDigestDrift = structuredClone(equivalentArm64);
    rootDigestDrift.packages.find(
        (component) => component.SPDXID === "SPDXRef-DocumentRoot-Image-sha256"
    ).versionInfo = "e".repeat(64);
    run(rootDigestDrift, 1);

    const duplicateAmd64 = structuredClone(source);
    const duplicateArm64 = structuredClone(equivalentArm64);
    for (const document of [duplicateAmd64, duplicateArm64]) {
        const duplicate = structuredClone(
            document.packages.find(
                (component) => component.name === "fixture-package"
            )
        );
        duplicate.SPDXID = "SPDXRef-Package-npm-fixture-duplicate";
        document.packages.splice(document.packages.length - 1, 0, duplicate);
    }
    fs.writeFileSync(amd64Path, JSON.stringify(duplicateAmd64));
    fs.writeFileSync(arm64Path, JSON.stringify(duplicateArm64));
    const duplicateResult = spawnSync(
        process.execPath,
        [
            checker,
            outputPath,
            amd64Path,
            arm64Path,
            `sha256:${"a".repeat(64)}`,
            `sha256:${"d".repeat(64)}`,
        ],
        { encoding: "utf8" }
    );
    assert.equal(duplicateResult.status, 0, duplicateResult.stderr);
    const duplicateEvidence = JSON.parse(fs.readFileSync(outputPath, "utf8"));
    assert.equal(duplicateEvidence.componentCount, 2);
    assert.equal(duplicateEvidence.components.length, 2);

    const versionDrift = structuredClone(equivalentArm64);
    versionDrift.packages.find(
        (component) => component.name === "fixture-package"
    ).versionInfo = "1.0.1";
    run(versionDrift, 1);

    const licenseDrift = structuredClone(equivalentArm64);
    licenseDrift.packages.find(
        (component) => component.name === "fixture-package"
    ).licenseDeclared = "Apache-2.0";
    run(licenseDrift, 1);

    const missingPurl = structuredClone(equivalentArm64);
    missingPurl.packages.find(
        (component) => component.name === "fixture-package"
    ).externalRefs = [];
    run(missingPurl, 1);
    console.log("Multi-architecture image inventory comparison tests passed.");
} finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
}
