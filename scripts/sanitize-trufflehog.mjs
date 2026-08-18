import fs from "node:fs";
import process from "node:process";

const inputPath = process.argv[2];
const outputPath = process.argv[3];
if (!inputPath || !outputPath)
    throw new Error("usage: sanitize-trufflehog.mjs INPUT OUTPUT");

const findings = [];
for (const [index, line] of fs
    .readFileSync(inputPath, "utf8")
    .split(/\r?\n/)
    .entries()) {
    if (!line.trim()) continue;
    let finding;
    try {
        finding = JSON.parse(line);
    } catch {
        throw new Error(`Malformed TruffleHog JSON on line ${index + 1}`);
    }
    if (
        typeof finding.DetectorName !== "string" ||
        typeof finding.Verified !== "boolean"
    ) {
        throw new Error(`Unexpected TruffleHog record on line ${index + 1}`);
    }
    const git = finding.SourceMetadata?.Data?.Git;
    const filesystem = finding.SourceMetadata?.Data?.Filesystem;
    const commit = git?.commit || process.env.TRUFFLEHOG_SUBJECT_COMMIT;
    const file = git?.file || filesystem?.file;
    const sourceLine = git?.line ?? filesystem?.line ?? 0;
    if (
        typeof file !== "string" ||
        !Number.isInteger(sourceLine) ||
        typeof commit !== "string" ||
        !/^[a-f0-9]{40}$/.test(commit)
    ) {
        throw new Error(
            `Missing exact TruffleHog source location on line ${index + 1}`
        );
    }
    findings.push({
        detector: finding.DetectorName,
        status: finding.Verified ? "verified" : "unknown",
        source: { commit, file, line: sourceLine },
    });
}

fs.writeFileSync(
    outputPath,
    JSON.stringify(
        { schemaVersion: 1, scanner: "trufflehog", findings },
        null,
        2
    ) + "\n",
    { flag: "wx", mode: 0o600 }
);
console.log(`Wrote ${findings.length} sanitized TruffleHog finding(s).`);
