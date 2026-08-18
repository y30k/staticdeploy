import fs from "node:fs";
import process from "node:process";

const inputPath = process.argv[2];
const outputPath = process.argv[3];
if (!inputPath || !outputPath) throw new Error("usage: sanitize-trufflehog.mjs INPUT OUTPUT");

const findings = [];
for (const [index, line] of fs.readFileSync(inputPath, "utf8").split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    let finding;
    try {
        finding = JSON.parse(line);
    } catch {
        throw new Error(`Malformed TruffleHog JSON on line ${index + 1}`);
    }
    if (typeof finding.DetectorName !== "string" || typeof finding.Verified !== "boolean") {
        throw new Error(`Unexpected TruffleHog record on line ${index + 1}`);
    }
    const git = finding.SourceMetadata?.Data?.Git;
    if (!git || typeof git.file !== "string" || !Number.isInteger(git.line) || typeof git.commit !== "string") {
        throw new Error(`Missing TruffleHog Git location on line ${index + 1}`);
    }
    findings.push({
        detector: finding.DetectorName,
        status: finding.Verified ? "verified" : "unknown",
        source: { commit: git.commit, file: git.file, line: git.line },
    });
}

fs.writeFileSync(
    outputPath,
    JSON.stringify({ schemaVersion: 1, scanner: "trufflehog", findings }, null, 2) + "\n",
    { flag: "wx", mode: 0o600 }
);
console.log(`Wrote ${findings.length} sanitized TruffleHog finding(s).`);
