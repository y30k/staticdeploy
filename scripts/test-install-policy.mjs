import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const checker = path.resolve("scripts/check-install-policy.mjs");
const temp = fs.mkdtempSync(
    path.join(os.tmpdir(), "staticdeploy-install-policy-")
);

const validConfig =
    "enableImmutableInstalls: true\n\n" +
    "enableScripts: false\n\n" +
    "nodeLinker: node-modules\n\n" +
    "npmMinimalAgeGate: 0\n";
const validLock = 'package@npm:1.0.0:\n  resolution: "package@npm:1.0.0"\n';
const validManifest = {
    dependenciesMeta: { "package@1.0.0": { built: false } },
    resolutions: { "child@npm:1.0.0": "npm:1.0.1" },
};
const validInventory = {
    defaultPolicy: "blocked",
    packages: [
        { package: "package", version: "1.0.0", allowed: false, scripts: {} },
    ],
};
const validResolutionsInventory = {
    defaultPolicy: "blocked",
    resolutions: [
        {
            selector: "child@npm:1.0.0",
            resolution: "npm:1.0.1",
            owner: "test owner",
            rationale: "test security correction",
            removalCondition: "remove after parent upgrade",
        },
    ],
};

function run(name, overrides = {}) {
    const directory = path.join(temp, name);
    fs.mkdirSync(directory);
    const paths = {
        config: path.join(directory, ".yarnrc.yml"),
        lock: path.join(directory, "yarn.lock"),
        manifest: path.join(directory, "package.json"),
        inventory: path.join(directory, "inventory.json"),
        resolutionsInventory: path.join(
            directory,
            "resolutions-inventory.json"
        ),
    };
    fs.writeFileSync(paths.config, overrides.config || validConfig);
    fs.writeFileSync(paths.lock, overrides.lock || validLock);
    fs.writeFileSync(
        paths.manifest,
        JSON.stringify(overrides.manifest || validManifest)
    );
    fs.writeFileSync(
        paths.inventory,
        JSON.stringify(overrides.inventory || validInventory)
    );
    fs.writeFileSync(
        paths.resolutionsInventory,
        JSON.stringify(
            overrides.resolutionsInventory || validResolutionsInventory
        )
    );
    return spawnSync(
        process.execPath,
        [
            checker,
            paths.config,
            paths.lock,
            paths.manifest,
            paths.inventory,
            paths.resolutionsInventory,
        ],
        { encoding: "utf8" }
    );
}

try {
    assert.equal(run("valid").status, 0, "valid policy must pass");
    assert.notEqual(
        run("scripts-enabled", {
            config: validConfig.replace(
                "enableScripts: false",
                "enableScripts: true"
            ),
        }).status,
        0
    );
    assert.notEqual(
        run("git-wildcard", {
            config: `${validConfig}approvedGitRepositories:\n  - "**"\n`,
        }).status,
        0
    );
    assert.notEqual(
        run("quoted-git-wildcard", {
            config: `${validConfig}"approvedGitRepositories":\n  - "**"\n`,
        }).status,
        0
    );
    assert.notEqual(
        run("git-resolution", {
            lock: 'package@git:https://example.invalid/repo.git#commit=abc:\n  resolution: "package@git:https://example.invalid/repo.git#commit=abc"\n',
        }).status,
        0
    );
    assert.notEqual(
        run("source-url-with-registry-substring", {
            lock: 'package@https://example.invalid/package-@npm:1.0.0.tgz:\n  resolution: "package@https://example.invalid/package-@npm:1.0.0.tgz"\n',
        }).status,
        0
    );
    assert.notEqual(
        run("non-builtin-patch-source", {
            lock: 'package@patch:package@https%3A//example.invalid/package.tgz#./patch.diff:\n  resolution: "package@patch:package@https%3A//example.invalid/package.tgz#./patch.diff"\n',
        }).status,
        0
    );
    assert.notEqual(
        run("unreviewed-allow", {
            manifest: {
                dependenciesMeta: {
                    ...validManifest.dependenciesMeta,
                    "other@2.0.0": { built: true },
                },
            },
        }).status,
        0
    );
    assert.notEqual(
        run("changed-decision", {
            manifest: {
                ...validManifest,
                dependenciesMeta: { "package@1.0.0": { built: true } },
            },
        }).status,
        0
    );
    assert.notEqual(
        run("unreviewed-resolution", {
            manifest: {
                ...validManifest,
                resolutions: {
                    ...validManifest.resolutions,
                    "other@npm:2.0.0": "npm:2.0.1",
                },
            },
        }).status,
        0
    );
    assert.notEqual(
        run("changed-resolution", {
            manifest: {
                ...validManifest,
                resolutions: { "child@npm:1.0.0": "npm:1.0.2" },
            },
        }).status,
        0
    );
    assert.notEqual(
        run("wildcard-resolution", {
            resolutionsInventory: {
                defaultPolicy: "blocked",
                resolutions: [
                    {
                        ...validResolutionsInventory.resolutions[0],
                        selector: "child@npm:*",
                    },
                ],
            },
        }).status,
        0
    );
    assert.notEqual(
        run("ownerless-resolution", {
            resolutionsInventory: {
                defaultPolicy: "blocked",
                resolutions: [
                    {
                        ...validResolutionsInventory.resolutions[0],
                        owner: "",
                    },
                ],
            },
        }).status,
        0
    );
    console.log("Install-policy negative tests passed.");
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}
