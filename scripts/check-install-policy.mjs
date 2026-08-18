import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const configPath = path.resolve(process.argv[2] || ".yarnrc.yml");
const lockPath = path.resolve(process.argv[3] || "yarn.lock");
const manifestPath = path.resolve(process.argv[4] || "package.json");
const inventoryPath = path.resolve(
    process.argv[5] || "config/install-scripts.json"
);

const config = fs.readFileSync(configPath, "utf8");
const lock = fs.readFileSync(lockPath, "utf8");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const inventory = JSON.parse(fs.readFileSync(inventoryPath, "utf8"));

const canonicalConfig =
    "enableImmutableInstalls: true\n\n" +
    "enableScripts: false\n\n" +
    "nodeLinker: node-modules\n\n" +
    "npmMinimalAgeGate: 0\n";
if (config !== canonicalConfig) {
    throw new Error(
        `${configPath} must match the reviewed canonical fail-closed configuration exactly`
    );
}

const packageName = "(?:@[^/@\\s]+/)?[^@/\\s]+";
const registryResolution = new RegExp(
    `^${packageName}@(npm|workspace):[^\\s]+$`
);
const builtinPatchResolution = new RegExp(
    `^${packageName}@patch:${packageName}@npm%3A[^#\\s]+#optional!builtin<compat/${packageName}>::version=[^&\\s]+&hash=[a-f0-9]+$`
);
for (const match of lock.matchAll(/^\s*resolution:\s*"([^"]+)"\s*$/gm)) {
    const resolution = match[1];
    if (
        !registryResolution.test(resolution) &&
        !builtinPatchResolution.test(resolution)
    ) {
        throw new Error(`Unsupported non-registry resolution: ${resolution}`);
    }
}

if (inventory.defaultPolicy !== "blocked")
    throw new Error("Install-script inventory must default to blocked");
const reviewed = new Map(
    inventory.packages.map((entry) => [
        `${entry.package}@${entry.version}`,
        entry.allowed,
    ])
);
const configured = manifest.dependenciesMeta || {};
for (const [locator, metadata] of Object.entries(configured)) {
    if (!reviewed.has(locator))
        throw new Error(`Unreviewed dependenciesMeta entry: ${locator}`);
    if (metadata.built !== reviewed.get(locator))
        throw new Error(
            `${locator} dependenciesMeta.built does not match inventory`
        );
}
for (const [locator, allowed] of reviewed) {
    if (configured[locator]?.built !== allowed)
        throw new Error(
            `Missing exact dependenciesMeta decision for ${locator}`
        );
}

console.log(
    "Pre-install policy is fail-closed: immutable, scripts disabled, no Git sources, and exact lifecycle decisions."
);
