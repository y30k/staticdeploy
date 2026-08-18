#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const script = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "generate-runtime-notices.mjs"
);
const sha256 = (value) =>
    `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;

function fixture() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-notices-"));
    fs.mkdirSync(path.join(root, "node_modules"), { recursive: true });
    fs.mkdirSync(path.join(root, "config"), { recursive: true });
    fs.mkdirSync(
        path.join(
            root,
            "docs/security/license-evidence/base-runtime-license-texts"
        ),
        { recursive: true }
    );
    fs.mkdirSync(
        path.join(root, "docs/security/license-evidence/npm-fallbacks"),
        { recursive: true }
    );
    fs.mkdirSync(path.join(root, "common"), { recursive: true });
    fs.writeFileSync(path.join(root, "LICENSE"), "project license\n");
    fs.writeFileSync(path.join(root, "node-license"), "node license\n");
    for (const name of [
        "Apache-2.0",
        "CC0-1.0",
        "GPL-2",
        "GPL-3",
        "LGPL-2.1",
        "LGPL-3",
        "MPL-2.0",
    ])
        fs.writeFileSync(path.join(root, "common", name), `${name} text\n`);
    fs.writeFileSync(
        path.join(
            root,
            "docs/security/license-evidence/base-runtime-license-texts/GCC-exception-3.1.txt"
        ),
        "GCC exception text\n"
    );
    writeFallbacks(root, []);
    return root;
}

function addPackage(root, name, manifest, files = {}) {
    const directory = path.join(root, "node_modules", ...name.split("/"));
    fs.mkdirSync(directory, { recursive: true });
    const manifestBytes = `${JSON.stringify({ name, ...manifest }, null, 2)}\n`;
    fs.writeFileSync(path.join(directory, "package.json"), manifestBytes);
    for (const [file, content] of Object.entries(files))
        fs.writeFileSync(path.join(directory, file), content);
    return { directory, manifestDigest: sha256(manifestBytes) };
}

function writeFallbacks(root, fallbacks) {
    fs.writeFileSync(
        path.join(root, "config/runtime-license-fallbacks.json"),
        `${JSON.stringify({ schemaVersion: 1, fallbacks }, null, 2)}\n`
    );
}

function run(root, expectedStatus = 0) {
    const result = spawnSync(process.execPath, [script, "notices.txt"], {
        cwd: root,
        encoding: "utf8",
        env: {
            ...process.env,
            RUNTIME_NOTICE_NODE_LICENSE: path.join(root, "node-license"),
            RUNTIME_NOTICE_COMMON_LICENSES: path.join(root, "common"),
        },
    });
    assert.equal(result.status, expectedStatus, result.stderr || result.stdout);
    return result;
}

{
    const root = fixture();
    try {
        addPackage(
            root,
            "hyphen-license",
            { version: "1.0.0", license: "MIT", author: "Exact Author" },
            { "LICENSE-MIT": "Copyright Exact Hyphen Author\n" }
        );
        addPackage(
            root,
            "readme-license",
            { version: "2.0.0", license: "ISC", author: "Readme Author" },
            {
                "README.md":
                    "# package\n\n## License\nCopyright Exact Readme Author\n",
            }
        );
        run(root);
        const output = fs.readFileSync(path.join(root, "notices.txt"), "utf8");
        assert.match(output, /--- LICENSE-MIT ---/);
        assert.match(output, /Copyright Exact Hyphen Author/);
        assert.match(output, /--- README\.md ---/);
        assert.match(output, /Copyright Exact Readme Author/);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
}

{
    const root = fixture();
    try {
        addPackage(root, "missing-notice", {
            version: "1.0.0",
            license: "MIT",
        });
        const result = run(root, 1);
        assert.match(
            result.stderr,
            /lacks exact package\/version\/license\/digest-bound notice evidence/
        );
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
}

{
    const root = fixture();
    try {
        const item = addPackage(root, "reviewed-fallback", {
            version: "3.0.0",
            license: "Apache-2.0",
            author: "Fallback Author",
        });
        const evidencePath =
            "docs/security/license-evidence/npm-fallbacks/reviewed-LICENSE";
        const evidence = "Exact reviewed fallback license\n";
        fs.writeFileSync(path.join(root, evidencePath), evidence);
        writeFallbacks(root, [
            {
                name: "reviewed-fallback",
                version: "3.0.0",
                license: "Apache-2.0",
                packageJsonDigest: item.manifestDigest,
                evidencePath,
                evidenceDigest: sha256(evidence),
                sourceReference: "https://example.test/pinned/revision/LICENSE",
            },
        ]);
        run(root);
        const output = fs.readFileSync(path.join(root, "notices.txt"), "utf8");
        assert.match(output, /Exact reviewed fallback license/);
        assert.match(output, /pinned\/revision\/LICENSE/);
        fs.appendFileSync(path.join(item.directory, "package.json"), " ");
        assert.match(run(root, 1).stderr, /lacks exact package\/version/);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
}

console.log("Runtime notice generation and fail-closed fixture tests passed.");
