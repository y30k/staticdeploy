import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const image = process.argv[2];
if (!image) throw new Error("usage: test-image-conformance.mjs IMAGE");

const docker = (...args) =>
    execFileSync("docker", args, { encoding: "utf8" }).trim();
const inspect = JSON.parse(docker("image", "inspect", image))[0];
assert.notEqual(inspect.Config.User, "", "runtime user must be explicit");
assert.notEqual(inspect.Config.User, "0", "runtime user must be non-root");
assert.notEqual(inspect.Config.User, "root", "runtime user must be non-root");
assert.match(inspect.Id, /^sha256:[a-f0-9]{64}$/);
assert.deepEqual(inspect.Config.Entrypoint, ["/nodejs/bin/node"]);
assert.deepEqual(inspect.Config.Cmd, ["build/server.js"]);
assert.ok(inspect.Config.Healthcheck, "runtime image must define healthcheck");

const history = docker(
    "history",
    "--no-trunc",
    "--format",
    "{{.CreatedBy}}",
    image
);
assert.doesNotMatch(history, /(?:yarn install|vite build|\btsc\b)/);
assert.doesNotMatch(history, /(?:npm|corepack|yarnpkg)/);

const layoutName = `staticdeploy-layout-${process.pid}`;
const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "staticdeploy-image-")
);
try {
    docker("create", "--name", layoutName, image);
    const archive = path.join(temporaryDirectory, "runtime.tar");
    execFileSync("docker", ["export", "--output", archive, layoutName]);
    const entries = execFileSync("tar", ["-tf", archive], {
        encoding: "utf8",
    })
        .split("\n")
        .filter(Boolean);
    const has = (candidate) =>
        entries.includes(candidate) || entries.includes(`${candidate}/`);
    assert.equal(has("opt/staticdeploy/staticdeploy/build/server.js"), true);
    assert.equal(
        has("opt/staticdeploy/management-console/build/index.html"),
        true
    );
    for (const forbidden of [
        "usr/local/lib/node_modules/npm",
        "usr/local/lib/node_modules/corepack",
        "opt/staticdeploy/yarn.lock",
    ])
        assert.equal(
            has(forbidden),
            false,
            `forbidden runtime path: ${forbidden}`
        );
    for (const entry of entries) {
        assert.doesNotMatch(
            entry,
            /^opt\/staticdeploy\/(?!node_modules\/)[^/]+\/src\//,
            `workspace source leaked: ${entry}`
        );
        assert.doesNotMatch(
            entry,
            /\/(?:test|tests|__tests__|spec|examples)\//,
            `test/example artifact leaked: ${entry}`
        );
        assert.doesNotMatch(
            entry,
            /\.(?:ts|tsx|map)$/,
            `build artifact leaked: ${entry}`
        );
    }
} finally {
    spawnSync("docker", ["rm", "-f", layoutName], { encoding: "utf8" });
    fs.rmSync(temporaryDirectory, { force: true, recursive: true });
}

const name = `staticdeploy-conformance-${process.pid}`;
let started = false;
try {
    docker(
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "-P",
        "-e",
        "MANAGEMENT_HOSTNAME=localhost",
        "-e",
        "ENABLE_MANAGEMENT_ENDPOINTS=false",
        "-e",
        "ENFORCE_AUTH=false",
        "-e",
        "CREATE_ROOT_USER=false",
        image
    );
    started = true;
    let container = JSON.parse(docker("inspect", name))[0];
    assert.equal(container.HostConfig.ReadonlyRootfs, true);
    assert.ok(container.HostConfig.CapDrop.includes("ALL"));
    assert.ok(
        container.HostConfig.SecurityOpt.includes("no-new-privileges:true")
    );
    const binding = container.NetworkSettings.Ports["80/tcp"]?.[0];
    assert.ok(binding?.HostPort, "container must publish its test port");

    const deadline = Date.now() + 90_000;
    while (
        Date.now() < deadline &&
        container.State.Health?.Status !== "healthy"
    ) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        container = JSON.parse(docker("inspect", name))[0];
        if (!container.State.Running) break;
    }
    assert.equal(
        container.State.Health?.Status,
        "healthy",
        "configured Docker healthcheck must pass with management endpoints disabled"
    );

    const status = await new Promise((resolve, reject) => {
        const request = http.get(
            {
                host: "127.0.0.1",
                port: Number(binding.HostPort),
                path: "/api/health",
                headers: { host: "localhost" },
                timeout: 2000,
            },
            (response) => {
                response.resume();
                resolve(response.statusCode);
            }
        );
        request.on("timeout", () => request.destroy());
        request.on("error", reject);
    });
    assert.equal(
        status,
        404,
        "disabled management routes must remain disabled"
    );
} finally {
    if (started) spawnSync("docker", ["stop", name], { encoding: "utf8" });
}

console.log(`Image conformance passed for ${inspect.Id}`);
