import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "staticdeploy-trufflehog-")
);
const input = path.join(directory, "raw.jsonl");
const output = path.join(directory, "sanitized.json");
const rawMarker = "fake-secret-value-that-must-not-survive";
const commit = "a".repeat(40);

try {
    fs.writeFileSync(
        input,
        JSON.stringify({
            DetectorName: "SyntheticDetector",
            Verified: true,
            Raw: rawMarker,
            RawV2: rawMarker,
            SourceMetadata: {
                Data: {
                    Git: { commit, file: "example.txt", line: 7 },
                },
            },
        }) + "\n"
    );
    const result = spawnSync(
        process.execPath,
        [path.resolve("scripts/sanitize-trufflehog.mjs"), input, output],
        {
            encoding: "utf8",
        }
    );
    assert.equal(result.status, 0, result.stderr);
    const sanitizedText = fs.readFileSync(output, "utf8");
    assert.ok(!sanitizedText.includes(rawMarker));
    assert.deepEqual(JSON.parse(sanitizedText).findings, [
        {
            detector: "SyntheticDetector",
            status: "verified",
            source: { commit, file: "example.txt", line: 7 },
        },
    ]);

    fs.rmSync(output);
    fs.writeFileSync(input, "not-json\n");
    assert.notEqual(
        spawnSync(process.execPath, [
            path.resolve("scripts/sanitize-trufflehog.mjs"),
            input,
            output,
        ]).status,
        0
    );
    assert.ok(!fs.existsSync(output));
    console.log("TruffleHog sanitizer tests passed.");
} finally {
    fs.rmSync(directory, { recursive: true, force: true });
}
