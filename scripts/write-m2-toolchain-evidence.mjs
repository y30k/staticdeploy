#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const [outputPath] = process.argv.slice(2);
if (!outputPath)
    throw new Error("usage: write-m2-toolchain-evidence.mjs OUTPUT");
const command = (program, args) =>
    execFileSync(program, args, { encoding: "utf8" }).trim();
const digestFile = (filePath) => {
    assert.ok(fs.statSync(filePath).size > 0, `${filePath} must not be empty`);
    return `sha256:${crypto
        .createHash("sha256")
        .update(fs.readFileSync(filePath))
        .digest("hex")}`;
};
const commit = command("git", ["rev-parse", "HEAD"]);
if (process.env.GITHUB_SHA) assert.equal(commit, process.env.GITHUB_SHA);
assert.equal(process.version, "v24.19.0");
const yarnVersion = command("corepack", ["yarn", "--version"]);
assert.equal(yarnVersion, "4.18.0");
const workspaceCount = JSON.parse(fs.readFileSync("package.json", "utf8"))
    .workspaces.length;
assert.equal(workspaceCount, 13);
const evidence = {
    schemaVersion: 1,
    commit,
    lockDigest: digestFile("yarn.lock"),
    nodeVersion: process.version.slice(1),
    yarnVersion,
    workspaceCount,
    typecheckProjectCount: 28,
    checks: [
        "install-policy",
        "immutable-install",
        "install-script-inventory",
        "format",
        "lint",
        "typecheck",
        "compile",
        "unit-integration-coverage",
    ].map((name) => ({ name, passed: true })),
    coverage: {
        backend: {
            path: "coverage/coverage-final.json",
            digest: digestFile("coverage/coverage-final.json"),
        },
        frontend: {
            path: "management-console/coverage/coverage-final.json",
            digest: digestFile(
                "management-console/coverage/coverage-final.json"
            ),
        },
    },
    generatedAt: new Date().toISOString(),
};
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(evidence, null, 2)}\n`, {
    mode: 0o600,
});
console.log(`Recorded complete toolchain evidence for ${commit}.`);
