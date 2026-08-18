#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [
    outputPath = "docs/security/license-evidence/m2-runtime-third-party-notices.txt",
] = process.argv.slice(2);
const root = process.cwd();
const modulesRoot = path.join(root, "node_modules");
const nodeLicensePath =
    process.env.RUNTIME_NOTICE_NODE_LICENSE || "/usr/local/LICENSE";
const commonLicensesRoot =
    process.env.RUNTIME_NOTICE_COMMON_LICENSES || "/usr/share/common-licenses";
const licenseName = /^(?:licen[cs]e|copying|notice)(?:[._-].*)?$/i;
const readmeName = /^readme(?:\..*)?$/i;
const packages = new Map();
const digest = (value) =>
    `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;

function visitModules(directory) {
    if (!fs.existsSync(directory)) return;
    for (const entry of fs
        .readdirSync(directory, { withFileTypes: true })
        .sort((a, b) => a.name.localeCompare(b.name))) {
        if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
        const entryPath = path.join(directory, entry.name);
        if (entry.name.startsWith("@")) {
            visitModules(entryPath);
            continue;
        }
        visitPackage(entryPath);
    }
}

function visitPackage(directory) {
    const manifestPath = path.join(directory, "package.json");
    if (!fs.existsSync(manifestPath)) return;
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    if (
        typeof manifest.name === "string" &&
        typeof manifest.version === "string" &&
        !manifest.name.startsWith("@staticdeploy/")
    ) {
        const directoryFiles = fs
            .readdirSync(directory, { withFileTypes: true })
            .filter((entry) => entry.isFile())
            .map((entry) => entry.name)
            .sort();
        let files = directoryFiles.filter((file) => licenseName.test(file));
        if (!files.length)
            files = directoryFiles.filter(
                (file) =>
                    readmeName.test(file) &&
                    /(?:licen[cs]e|copyright)/i.test(
                        fs.readFileSync(path.join(directory, file), "utf8")
                    )
            );
        const key = `${manifest.name}@${manifest.version}`;
        if (!packages.has(key))
            packages.set(key, {
                name: manifest.name,
                version: manifest.version,
                declared:
                    typeof manifest.license === "string"
                        ? manifest.license
                        : "NOASSERTION",
                attribution: manifest.author ?? manifest.repository ?? null,
                manifestDigest: digest(fs.readFileSync(manifestPath)),
                fallbackSource: null,
                files: files.map((file) => ({
                    name: file,
                    content: fs.readFileSync(
                        path.join(directory, file),
                        "utf8"
                    ),
                })),
            });
    }
    visitModules(path.join(directory, "node_modules"));
}

visitModules(modulesRoot);
if (!packages.size) throw new Error("No production registry packages found");
const fallbackPolicy = JSON.parse(
    fs.readFileSync(
        path.join(root, "config/runtime-license-fallbacks.json"),
        "utf8"
    )
);
if (
    fallbackPolicy.schemaVersion !== 1 ||
    !Array.isArray(fallbackPolicy.fallbacks)
)
    throw new Error("Invalid runtime license fallback policy");
const fallbacks = new Map();
for (const fallback of fallbackPolicy.fallbacks) {
    const keys = Object.keys(fallback).sort();
    const expected = [
        "evidenceDigest",
        "evidencePath",
        "license",
        "name",
        "packageJsonDigest",
        "sourceReference",
        "version",
    ].sort();
    if (JSON.stringify(keys) !== JSON.stringify(expected))
        throw new Error("Runtime license fallback has unexpected fields");
    const key = `${fallback.name}@${fallback.version}`;
    if (fallbacks.has(key))
        throw new Error(`Duplicate runtime fallback: ${key}`);
    if (
        !fallback.evidencePath.startsWith(
            "docs/security/license-evidence/npm-fallbacks/"
        ) ||
        path.normalize(fallback.evidencePath) !== fallback.evidencePath
    )
        throw new Error(`Unsafe runtime fallback path: ${key}`);
    const evidence = fs.readFileSync(path.join(root, fallback.evidencePath));
    if (digest(evidence) !== fallback.evidenceDigest)
        throw new Error(`Runtime fallback evidence digest mismatch: ${key}`);
    fallbacks.set(key, { ...fallback, evidence });
}
const usedFallbacks = new Set();
for (const item of packages.values()) {
    if (item.files.length) continue;
    const key = `${item.name}@${item.version}`;
    const fallback = fallbacks.get(key);
    if (
        !fallback ||
        fallback.license !== item.declared ||
        fallback.packageJsonDigest !== item.manifestDigest
    )
        throw new Error(
            `${key} lacks exact package/version/license/digest-bound notice evidence`
        );
    usedFallbacks.add(key);
    item.fallbackSource = fallback.sourceReference;
    item.files = [
        {
            name: fallback.evidencePath,
            content: fallback.evidence.toString("utf8"),
        },
    ];
}
for (const key of fallbacks.keys())
    if (!usedFallbacks.has(key))
        throw new Error(`Unused runtime fallback: ${key}`);

const sections = [
    "StaticDeploy M2 runtime third-party notices",
    "",
    "This deterministic bundle contains the retained license/notice files for",
    "the exact production npm package closure. Base-runtime and application",
    "license texts are appended from their retained build inputs.",
    "",
];
for (const item of [...packages.values()].sort((a, b) =>
    `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`)
)) {
    sections.push("=".repeat(78));
    sections.push(`${item.name}@${item.version}`);
    sections.push(`Declared package license: ${item.declared}`);
    sections.push(
        `Package attribution metadata: ${JSON.stringify(item.attribution)}`
    );
    if (item.fallbackSource)
        sections.push(`Exact fallback source: ${item.fallbackSource}`);
    for (const file of item.files) {
        sections.push(`--- ${file.name} ---`);
        sections.push(file.content.trimEnd());
    }
    sections.push("");
}
for (const [label, file] of [
    ["StaticDeploy application", path.join(root, "LICENSE")],
    ["Node.js runtime", nodeLicensePath],
    ["Apache-2.0 standard text", path.join(commonLicensesRoot, "Apache-2.0")],
    ["CC0-1.0 standard text", path.join(commonLicensesRoot, "CC0-1.0")],
    ["GPL-2.0 standard text", path.join(commonLicensesRoot, "GPL-2")],
    ["GPL-3.0 standard text", path.join(commonLicensesRoot, "GPL-3")],
    ["LGPL-2.1 standard text", path.join(commonLicensesRoot, "LGPL-2.1")],
    ["LGPL-3.0 standard text", path.join(commonLicensesRoot, "LGPL-3")],
    ["MPL-2.0 standard text", path.join(commonLicensesRoot, "MPL-2.0")],
    [
        "GCC Runtime Library Exception 3.1",
        path.join(
            root,
            "docs/security/license-evidence/base-runtime-license-texts/GCC-exception-3.1.txt"
        ),
    ],
]) {
    if (!fs.existsSync(file))
        throw new Error(`Missing retained license input: ${file}`);
    sections.push(
        "=".repeat(78),
        label,
        fs.readFileSync(file, "utf8").trimEnd(),
        ""
    );
}
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${sections.join("\n")}\n`);
console.log(
    `Generated notices for ${packages.size} registry package versions.`
);
