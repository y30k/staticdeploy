#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const [outputPath, ...specifications] = process.argv.slice(2);
if (!outputPath || specifications.length !== 2)
    throw new Error(
        "usage: write-multiarch-image-evidence.mjs OUTPUT linux/amd64=IMAGE,CONFORMANCE_JSON,METADATA_JSON,OCI_ARCHIVE linux/arm64=IMAGE,CONFORMANCE_JSON,METADATA_JSON,OCI_ARCHIVE"
    );
const command = (program, args) =>
    execFileSync(program, args, { encoding: "utf8" }).trim();
const commit = command("git", ["rev-parse", "HEAD"]);
assert.match(commit, /^[a-f0-9]{40}$/);
if (process.env.GITHUB_SHA)
    assert.equal(
        commit,
        process.env.GITHUB_SHA,
        "workflow must build exact HEAD"
    );
const lockDigest = `sha256:${crypto
    .createHash("sha256")
    .update(fs.readFileSync("yarn.lock"))
    .digest("hex")}`;
const requiredPlatforms = new Set(["linux/amd64", "linux/arm64"]);
const images = specifications
    .map((specification) => {
        const separator = specification.indexOf("=");
        assert.ok(
            separator > 0,
            `invalid image specification: ${specification}`
        );
        const platform = specification.slice(0, separator);
        const [
            image,
            conformancePath,
            metadataPath,
            archivePath,
            ...unexpected
        ] = specification.slice(separator + 1).split(",");
        assert.ok(
            requiredPlatforms.delete(platform),
            `unexpected platform: ${platform}`
        );
        assert.ok(
            image &&
                conformancePath &&
                metadataPath &&
                archivePath &&
                !unexpected.length,
            `incomplete image evidence for ${platform}`
        );
        const inspect = JSON.parse(
            command("docker", ["image", "inspect", image])
        )[0];
        assert.equal(`${inspect.Os}/${inspect.Architecture}`, platform);
        assert.match(inspect.Id, /^sha256:[a-f0-9]{64}$/);
        assert.equal(
            inspect.Config.Labels?.["org.opencontainers.image.revision"],
            commit,
            `${platform} image must identify exact source commit`
        );
        assert.ok(
            Array.isArray(inspect.RepoDigests),
            `${platform} registry state must be explicit`
        );
        assert.deepEqual(
            inspect.RepoDigests,
            [],
            `${platform} image must remain local and registry-negative`
        );
        assert.equal(inspect.Config.User, "65532:65532");
        assert.deepEqual(inspect.Config.Entrypoint, ["/nodejs/bin/node"]);
        assert.deepEqual(inspect.Config.Cmd, ["build/server.js"]);
        assert.ok(Number.isSafeInteger(inspect.Size) && inspect.Size > 0);
        const conformance = JSON.parse(
            fs.readFileSync(conformancePath, "utf8")
        );
        assert.deepEqual(Object.keys(conformance).sort(), [
            "configDigest",
            "passed",
            "platform",
            "schemaVersion",
        ]);
        assert.deepEqual(conformance, {
            schemaVersion: 1,
            platform,
            configDigest: inspect.Id,
            passed: true,
        });
        const conformanceDigest = `sha256:${crypto
            .createHash("sha256")
            .update(fs.readFileSync(conformancePath))
            .digest("hex")}`;
        const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
        assert.equal(metadata["containerimage.config.digest"], inspect.Id);
        assert.match(
            metadata["containerimage.digest"],
            /^sha256:[a-f0-9]{64}$/
        );
        assert.equal(
            metadata["containerimage.descriptor"]?.digest,
            metadata["containerimage.digest"]
        );
        const tarEntry = (entry) =>
            execFileSync("tar", ["-xOf", archivePath, entry], {
                maxBuffer: 512 * 1024 * 1024,
            });
        const index = JSON.parse(tarEntry("index.json"));
        assert.equal(index.schemaVersion, 2);
        assert.equal(index.manifests?.length, 1);
        const descriptor = index.manifests[0];
        assert.equal(descriptor.digest, metadata["containerimage.digest"]);
        assert.equal(
            `${descriptor.platform?.os}/${descriptor.platform?.architecture}`,
            platform
        );
        const verifyBlob = (blobDigest) => {
            assert.match(blobDigest, /^sha256:[a-f0-9]{64}$/);
            const bytes = tarEntry(
                `blobs/sha256/${blobDigest.slice("sha256:".length)}`
            );
            assert.equal(
                `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`,
                blobDigest
            );
            return bytes;
        };
        const manifest = JSON.parse(verifyBlob(descriptor.digest));
        assert.equal(manifest.config?.digest, inspect.Id);
        assert.ok(Array.isArray(manifest.layers) && manifest.layers.length > 0);
        const verifiedConfig = JSON.parse(verifyBlob(manifest.config.digest));
        assert.equal(
            `${verifiedConfig.os}/${verifiedConfig.architecture}`,
            platform
        );
        for (const layer of manifest.layers) verifyBlob(layer.digest);
        return {
            platform,
            image,
            configDigest: inspect.Id,
            manifestDigest: descriptor.digest,
            layerDigests: manifest.layers.map((layer) => layer.digest),
            sizeBytes: inspect.Size,
            revision: commit,
            user: inspect.Config.User,
            entrypoint: inspect.Config.Entrypoint,
            command: inspect.Config.Cmd,
            repoDigests: [],
            conformance: {
                path: path.basename(conformancePath),
                digest: conformanceDigest,
                passed: true,
            },
        };
    })
    .sort((left, right) => left.platform.localeCompare(right.platform));
assert.equal(
    requiredPlatforms.size,
    0,
    "both required platforms must be present"
);
assert.equal(
    new Set(images.map((image) => image.configDigest)).size,
    images.length,
    "platform images must have distinct configuration digests"
);
assert.equal(
    new Set(images.map((image) => image.manifestDigest)).size,
    images.length,
    "platform images must have distinct manifest digests"
);
const report = {
    schemaVersion: 1,
    commit,
    lockDigest,
    generatedAt: new Date().toISOString(),
    registryNegative: images.every((image) => image.repoDigests.length === 0),
    images,
};
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, {
    mode: 0o600,
});
console.log(
    `Recorded registry-negative multi-architecture evidence for ${commit}.`
);
