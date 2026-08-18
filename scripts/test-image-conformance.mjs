import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import http from "node:http";
import process from "node:process";

const image = process.argv[2];
if (!image) throw new Error("usage: test-image-conformance.mjs IMAGE");

const docker = (...args) =>
    execFileSync("docker", args, { encoding: "utf8" }).trim();
const inspect = JSON.parse(docker("image", "inspect", image))[0];
assert.equal(inspect.Config.User, "node", "runtime image must use node user");
assert.match(inspect.Id, /^sha256:[a-f0-9]{64}$/);
assert.deepEqual(inspect.Config.Cmd, ["node", "build/server.js"]);
assert.ok(inspect.Config.Healthcheck, "runtime image must define healthcheck");

const history = docker(
    "history",
    "--no-trunc",
    "--format",
    "{{.CreatedBy}}",
    image
);
assert.doesNotMatch(history, /(?:yarn install|vite build|\btsc\b)/);

const layout = spawnSync(
    "docker",
    [
        "run",
        "--rm",
        "--entrypoint",
        "sh",
        image,
        "-c",
        [
            'test "$(id -u)" = 1000',
            "! command -v npm",
            "! command -v yarn",
            "! test -e /opt/staticdeploy/staticdeploy/src",
            "! test -e /opt/staticdeploy/yarn.lock",
            "! find /opt/staticdeploy/node_modules -type d -name test -print -quit | grep -q .",
            "! find /opt/staticdeploy/node_modules -type d -name tests -print -quit | grep -q .",
            "! find /opt/staticdeploy/node_modules -type d -name __tests__ -print -quit | grep -q .",
            "test -f /opt/staticdeploy/staticdeploy/build/server.js",
            "test -f /opt/staticdeploy/management-console/build/index.html",
        ].join("; "),
    ],
    { encoding: "utf8" }
);
assert.equal(layout.status, 0, layout.stderr || layout.stdout);

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
        "ENFORCE_AUTH=false",
        "-e",
        "CREATE_ROOT_USER=false",
        image
    );
    started = true;
    const container = JSON.parse(docker("inspect", name))[0];
    assert.equal(container.HostConfig.ReadonlyRootfs, true);
    assert.ok(container.HostConfig.CapDrop.includes("ALL"));
    assert.ok(
        container.HostConfig.SecurityOpt.includes("no-new-privileges:true")
    );
    const binding = container.NetworkSettings.Ports["80/tcp"]?.[0];
    assert.ok(binding?.HostPort, "container must publish its test port");

    const deadline = Date.now() + 90_000;
    let healthy = false;
    while (Date.now() < deadline && !healthy) {
        healthy = await new Promise((resolve) => {
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
                    resolve(response.statusCode === 200);
                }
            );
            request.on("timeout", () => request.destroy());
            request.on("error", () => resolve(false));
        });
        if (!healthy) await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    assert.equal(healthy, true, "restricted runtime health smoke must pass");
} finally {
    if (started) spawnSync("docker", ["stop", name], { encoding: "utf8" });
}

console.log(`Image conformance passed for ${inspect.Id}`);
