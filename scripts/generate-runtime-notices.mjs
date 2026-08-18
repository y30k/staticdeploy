#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const [
    outputPath = "docs/security/license-evidence/m2-runtime-third-party-notices.txt",
] = process.argv.slice(2);
const root = process.cwd();
const modulesRoot = path.join(root, "node_modules");
const licenseName = /^(?:licen[cs]e|copying|notice)(?:\..*)?$/i;
const packages = new Map();

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
        const files = fs
            .readdirSync(directory, { withFileTypes: true })
            .filter((entry) => entry.isFile() && licenseName.test(entry.name))
            .map((entry) => entry.name)
            .sort();
        const key = `${manifest.name}@${manifest.version}`;
        if (!packages.has(key))
            packages.set(key, {
                name: manifest.name,
                version: manifest.version,
                declared:
                    typeof manifest.license === "string"
                        ? manifest.license
                        : "NOASSERTION",
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
const exemplars = new Map();
for (const item of packages.values())
    if (item.files.length && !exemplars.has(item.declared))
        exemplars.set(item.declared, item);
for (const item of packages.values()) {
    if (item.files.length) continue;
    const exemplar = exemplars.get(item.declared);
    if (!exemplar)
        throw new Error(
            `${item.name}@${item.version} has no license file or exact-expression exemplar for ${item.declared}`
        );
    item.files = exemplar.files.map((file) => ({
        name: `shared ${item.declared} text from ${exemplar.name}@${exemplar.version}/${file.name}`,
        content: file.content,
    }));
}

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
    for (const file of item.files) {
        sections.push(`--- ${file.name} ---`);
        sections.push(file.content.trimEnd());
    }
    sections.push("");
}
for (const [label, file] of [
    ["StaticDeploy application", path.join(root, "LICENSE")],
    ["Node.js runtime", "/usr/local/LICENSE"],
    ["Apache-2.0 standard text", "/usr/share/common-licenses/Apache-2.0"],
    ["CC0-1.0 standard text", "/usr/share/common-licenses/CC0-1.0"],
    ["GPL-2.0 standard text", "/usr/share/common-licenses/GPL-2"],
    ["GPL-3.0 standard text", "/usr/share/common-licenses/GPL-3"],
    ["LGPL-2.1 standard text", "/usr/share/common-licenses/LGPL-2.1"],
    ["LGPL-3.0 standard text", "/usr/share/common-licenses/LGPL-3"],
    ["MPL-2.0 standard text", "/usr/share/common-licenses/MPL-2.0"],
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
