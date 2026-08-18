#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const writer = path.resolve("scripts/write-multiarch-image-evidence.mjs");
const commit = execFileSync("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
}).trim();
const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "multiarch-evidence-")
);
try {
    const docker = path.join(temporaryDirectory, "docker");
    fs.writeFileSync(
        docker,
        `#!/usr/bin/env node
const fs = require("node:fs");
const fixtures = JSON.parse(fs.readFileSync(process.env.INSPECT_FIXTURES, "utf8"));
const image = process.argv.at(-1);
if (!fixtures[image]) process.exit(2);
process.stdout.write(JSON.stringify([fixtures[image]]));
`
    );
    fs.chmodSync(docker, 0o755);
    const fixturePath = path.join(temporaryDirectory, "inspect.json");
    const outputPath = path.join(temporaryDirectory, "evidence.json");
    const sha256 = (value) =>
        `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
    const createOciArchive = (
        architecture,
        configArchitecture = architecture
    ) => {
        const directory = path.join(temporaryDirectory, `oci-${architecture}`);
        const blobs = path.join(directory, "blobs/sha256");
        fs.mkdirSync(blobs, { recursive: true });
        const layer = Buffer.from(`exact-${architecture}-layer`);
        const layerDigest = sha256(layer);
        const config = Buffer.from(
            JSON.stringify({
                architecture: configArchitecture,
                os: "linux",
                rootfs: { type: "layers" },
            })
        );
        const configDigest = sha256(config);
        const manifest = Buffer.from(
            JSON.stringify({
                schemaVersion: 2,
                mediaType: "application/vnd.oci.image.manifest.v1+json",
                config: {
                    mediaType: "application/vnd.oci.image.config.v1+json",
                    digest: configDigest,
                    size: config.length,
                },
                layers: [
                    {
                        mediaType: "application/vnd.oci.image.layer.v1.tar",
                        digest: layerDigest,
                        size: layer.length,
                    },
                ],
            })
        );
        const manifestDigest = sha256(manifest);
        for (const [blobDigest, bytes] of [
            [layerDigest, layer],
            [configDigest, config],
            [manifestDigest, manifest],
        ])
            fs.writeFileSync(
                path.join(blobs, blobDigest.slice("sha256:".length)),
                bytes
            );
        fs.writeFileSync(
            path.join(directory, "oci-layout"),
            JSON.stringify({ imageLayoutVersion: "1.0.0" })
        );
        fs.writeFileSync(
            path.join(directory, "index.json"),
            JSON.stringify({
                schemaVersion: 2,
                mediaType: "application/vnd.oci.image.index.v1+json",
                manifests: [
                    {
                        mediaType: "application/vnd.oci.image.manifest.v1+json",
                        digest: manifestDigest,
                        size: manifest.length,
                        platform: { os: "linux", architecture },
                    },
                ],
            })
        );
        const archive = path.join(temporaryDirectory, `${architecture}.tar`);
        execFileSync("tar", [
            "-cf",
            archive,
            "-C",
            directory,
            "oci-layout",
            "index.json",
            "blobs",
        ]);
        return { archive, configDigest, manifestDigest, layerDigest };
    };
    const oci = {
        amd64: createOciArchive("amd64"),
        arm64: createOciArchive("arm64"),
    };
    const makeInspect = (architecture) => ({
        Os: "linux",
        Architecture: architecture,
        Id: oci[architecture].configDigest,
        Size: architecture === "amd64" ? 166_000_000 : 160_000_000,
        RepoDigests: [],
        Config: {
            User: "65532:65532",
            Entrypoint: ["/nodejs/bin/node"],
            Cmd: ["build/server.js"],
            Labels: { "org.opencontainers.image.revision": commit },
        },
    });
    const validFixtures = {
        "fixture:amd64": makeInspect("amd64"),
        "fixture:arm64": makeInspect("arm64"),
    };
    const conformancePaths = {
        amd64: path.join(temporaryDirectory, "conformance-amd64.json"),
        arm64: path.join(temporaryDirectory, "conformance-arm64.json"),
    };
    const metadataPaths = {
        amd64: path.join(temporaryDirectory, "metadata-amd64.json"),
        arm64: path.join(temporaryDirectory, "metadata-arm64.json"),
    };
    const validConformance = {
        amd64: {
            schemaVersion: 1,
            platform: "linux/amd64",
            configDigest: validFixtures["fixture:amd64"].Id,
            passed: true,
        },
        arm64: {
            schemaVersion: 1,
            platform: "linux/arm64",
            configDigest: validFixtures["fixture:arm64"].Id,
            passed: true,
        },
    };
    const validMetadata = {
        amd64: {
            "containerimage.config.digest": oci.amd64.configDigest,
            "containerimage.digest": oci.amd64.manifestDigest,
            "containerimage.descriptor": {
                digest: oci.amd64.manifestDigest,
            },
        },
        arm64: {
            "containerimage.config.digest": oci.arm64.configDigest,
            "containerimage.digest": oci.arm64.manifestDigest,
            "containerimage.descriptor": {
                digest: oci.arm64.manifestDigest,
            },
        },
    };
    const run = (
        fixtures,
        expectedStatus,
        conformance = validConformance,
        metadata = validMetadata,
        archives = oci
    ) => {
        fs.writeFileSync(fixturePath, JSON.stringify(fixtures));
        for (const architecture of ["amd64", "arm64"]) {
            fs.writeFileSync(
                conformancePaths[architecture],
                `${JSON.stringify(conformance[architecture], null, 2)}\n`
            );
            fs.writeFileSync(
                metadataPaths[architecture],
                JSON.stringify(metadata[architecture])
            );
        }
        const result = spawnSync(
            process.execPath,
            [
                writer,
                outputPath,
                `linux/amd64=fixture:amd64,${conformancePaths.amd64},${metadataPaths.amd64},${archives.amd64.archive}`,
                `linux/arm64=fixture:arm64,${conformancePaths.arm64},${metadataPaths.arm64},${archives.arm64.archive}`,
            ],
            {
                encoding: "utf8",
                env: {
                    ...process.env,
                    GITHUB_SHA: commit,
                    INSPECT_FIXTURES: fixturePath,
                    PATH: `${temporaryDirectory}:${process.env.PATH}`,
                },
            }
        );
        assert.equal(result.status, expectedStatus, result.stderr);
        return result;
    };

    run(validFixtures, 0);
    const evidence = JSON.parse(fs.readFileSync(outputPath, "utf8"));
    assert.equal(evidence.commit, commit);
    assert.equal(evidence.registryNegative, true);
    assert.deepEqual(
        evidence.images.map((image) => image.platform),
        ["linux/amd64", "linux/arm64"]
    );
    assert.ok(
        evidence.images.every((image) => image.conformance.passed === true)
    );
    for (const image of evidence.images) {
        const architecture = image.platform.slice("linux/".length);
        assert.equal(
            image.conformance.path,
            path.basename(conformancePaths[architecture])
        );
        assert.equal(
            image.conformance.digest,
            sha256(fs.readFileSync(conformancePaths[architecture]))
        );
    }
    assert.ok(evidence.images.every((image) => image.repoDigests.length === 0));
    assert.ok(
        evidence.images.every((image) => image.layerDigests.length === 1)
    );

    run(
        {
            ...validFixtures,
            "fixture:arm64": {
                ...validFixtures["fixture:arm64"],
                RepoDigests: ["registry.example/image@sha256:unexpected"],
            },
        },
        1
    );
    run(
        {
            ...validFixtures,
            "fixture:arm64": {
                ...validFixtures["fixture:arm64"],
                RepoDigests: undefined,
            },
        },
        1
    );
    run(
        {
            ...validFixtures,
            "fixture:arm64": {
                ...validFixtures["fixture:arm64"],
                Architecture: "amd64",
            },
        },
        1
    );
    run(validFixtures, 1, {
        ...validConformance,
        arm64: { ...validConformance.arm64, passed: false },
    });
    run(validFixtures, 1, validConformance, {
        ...validMetadata,
        arm64: {
            ...validMetadata.arm64,
            "containerimage.digest":
                validMetadata.amd64["containerimage.digest"],
            "containerimage.descriptor": {
                ...validMetadata.arm64["containerimage.descriptor"],
                digest: validMetadata.amd64["containerimage.digest"],
            },
        },
    });
    run(
        {
            ...validFixtures,
            "fixture:arm64": {
                ...validFixtures["fixture:arm64"],
                Id: validFixtures["fixture:amd64"].Id,
            },
        },
        1
    );
    const wrongPlatformArchive = createOciArchive("arm64", "amd64");
    const wrongPlatformFixtures = {
        ...validFixtures,
        "fixture:arm64": {
            ...validFixtures["fixture:arm64"],
            Id: wrongPlatformArchive.configDigest,
        },
    };
    const wrongPlatformConformance = {
        ...validConformance,
        arm64: {
            ...validConformance.arm64,
            configDigest: wrongPlatformArchive.configDigest,
        },
    };
    const wrongPlatformMetadata = {
        ...validMetadata,
        arm64: {
            "containerimage.config.digest": wrongPlatformArchive.configDigest,
            "containerimage.digest": wrongPlatformArchive.manifestDigest,
            "containerimage.descriptor": {
                digest: wrongPlatformArchive.manifestDigest,
            },
        },
    };
    run(
        wrongPlatformFixtures,
        1,
        wrongPlatformConformance,
        wrongPlatformMetadata,
        { ...oci, arm64: wrongPlatformArchive }
    );
    console.log("Multi-architecture evidence generation tests passed.");
} finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
}
