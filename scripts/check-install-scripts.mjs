import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const lifecycleNames = ["preinstall", "install", "postinstall"];
const inventoryPath = path.resolve(
    process.argv[2] || "config/install-scripts.json"
);
const inventory = JSON.parse(fs.readFileSync(inventoryPath, "utf8"));

if (inventory.defaultPolicy !== "blocked") {
    throw new Error(
        `Default install-script policy must be blocked, got ${inventory.defaultPolicy}`
    );
}

const rootManifest = JSON.parse(
    fs.readFileSync(path.resolve("package.json"), "utf8")
);
const expected = new Set();
for (const entry of inventory.packages) {
    const locator = `${entry.package}@${entry.version}`;
    const configured = rootManifest.dependenciesMeta?.[locator]?.built;
    if (configured !== entry.allowed) {
        throw new Error(
            `${locator} dependenciesMeta.built must be ${entry.allowed}`
        );
    }
    for (const [script, command] of Object.entries(entry.scripts)) {
        expected.add(`${locator}\t${script}\t${command}`);
    }
}

const actual = new Set();
const visited = new Set();

function inspectPackage(packageDirectory) {
    const manifestPath = path.join(packageDirectory, "package.json");
    if (!fs.existsSync(manifestPath)) return;

    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    for (const script of lifecycleNames) {
        const command = manifest.scripts?.[script];
        if (command)
            actual.add(
                `${manifest.name}@${manifest.version}\t${script}\t${command}`
            );
    }
    inspectNodeModules(path.join(packageDirectory, "node_modules"));
}

function inspectNodeModules(nodeModulesDirectory) {
    let realDirectory;
    try {
        realDirectory = fs.realpathSync(nodeModulesDirectory);
    } catch {
        return;
    }
    if (visited.has(realDirectory)) return;
    visited.add(realDirectory);

    for (const entry of fs.readdirSync(nodeModulesDirectory, {
        withFileTypes: true,
    })) {
        if (
            !entry.isDirectory() ||
            entry.isSymbolicLink() ||
            entry.name === ".bin"
        )
            continue;
        const entryPath = path.join(nodeModulesDirectory, entry.name);
        if (entry.name.startsWith("@")) {
            for (const scopedEntry of fs.readdirSync(entryPath, {
                withFileTypes: true,
            })) {
                if (
                    scopedEntry.isDirectory() &&
                    !scopedEntry.isSymbolicLink()
                ) {
                    inspectPackage(path.join(entryPath, scopedEntry.name));
                }
            }
        } else {
            inspectPackage(entryPath);
        }
    }
}

inspectNodeModules(path.resolve("node_modules"));

const missing = [...expected].filter((entry) => !actual.has(entry)).sort();
const unreviewed = [...actual].filter((entry) => !expected.has(entry)).sort();
if (missing.length || unreviewed.length) {
    if (missing.length)
        console.error(
            "Reviewed scripts no longer resolved:\n" + missing.join("\n")
        );
    if (unreviewed.length)
        console.error(
            "Unreviewed dependency scripts resolved:\n" + unreviewed.join("\n")
        );
    process.exitCode = 1;
} else {
    const allowed = inventory.packages.filter((entry) => entry.allowed).length;
    console.log(
        `Install-script inventory matches ${inventory.packages.length} reviewed package versions (${actual.size} lifecycle scripts; ${allowed} package allowed).`
    );
}
