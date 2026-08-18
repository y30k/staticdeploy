import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = new URL("../", import.meta.url);
const build = new URL("build/", root);
const html = fs.readFileSync(new URL("index.html", build), "utf8");

assert.match(html, /<script id="app-config" src="\/app-config\.js"><\/script>/);
const script = html.match(
    /<script type="module"[^>]+src="(\/assets\/[^"]+\.js)"/
);
const stylesheet = html.match(
    /<link rel="stylesheet"[^>]+href="(\/assets\/[^"]+\.css)"/
);
assert.ok(script, "Built HTML must reference a root-relative Vite script");
assert.ok(
    stylesheet,
    "Built HTML must reference a root-relative Vite stylesheet"
);
assert.ok(
    html.indexOf('id="app-config"') < html.indexOf('type="module"'),
    "Runtime configuration must load before the application entry"
);

for (const assetUrl of [script[1], stylesheet[1]]) {
    const asset = path.join(new URL(build).pathname, assetUrl);
    assert.ok(fs.statSync(asset).size > 0, `Missing built asset ${assetUrl}`);
}

const assetsDirectory = new URL("assets/", build);
const javascriptAssets = fs
    .readdirSync(assetsDirectory, { recursive: true })
    .filter(
        (asset) => typeof asset === "string" && /\.(?:js|mjs)$/.test(asset)
    );
assert.ok(javascriptAssets.length > 0, "Build must emit JavaScript assets");
for (const asset of javascriptAssets) {
    const javascript = fs.readFileSync(
        new URL(asset.replaceAll(path.sep, "/"), assetsDirectory),
        "utf8"
    );
    assert.doesNotMatch(
        javascript,
        /\beval\s*\(/,
        `${asset} must not require unsafe-eval`
    );
    assert.doesNotMatch(
        javascript,
        /new\s+Function\s*\(/,
        `${asset} must not construct code dynamically`
    );
}
assert.ok(
    fs.existsSync(new URL("app-config.js", build)),
    "Vite development defaults must be included in the standalone build"
);
console.log(
    "Built console has root-relative deep-route assets and an eval-free script bundle."
);
