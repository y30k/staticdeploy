import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const rootManifest = JSON.parse(fs.readFileSync("package.json", "utf8"));
const expectedWorkspaces = [
    "management-console",
    "cli",
    "core",
    "http-adapters",
    "jwt-authentication-strategy",
    "memory-storages",
    "oidc-authentication-strategy",
    "pg-s3-storages",
    "sdk",
    "serve-static",
    "staticdeploy",
    "storages-test-suite",
    "tar-archiver",
];
assert.deepEqual(rootManifest.workspaces, expectedWorkspaces);

const removedScripts = [
    "lint",
    "lint:eslint",
    "lint:prettier",
    "lint:tslint",
    "prettier",
    "prettify",
];
const centralizedDependencies = [
    "babel-eslint",
    "eslint",
    "eslint-plugin-react",
    "husky",
    "prettier",
    "tslint",
    "tslint-config-prettier",
    "tslint-react",
    "typescript-eslint",
];
for (const workspace of expectedWorkspaces) {
    const manifestPath = path.join(workspace, "package.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    for (const script of removedScripts) {
        assert.equal(
            manifest.scripts?.[script],
            undefined,
            `${manifestPath} must use the centralized ${script} command`
        );
    }
    for (const dependency of centralizedDependencies) {
        assert.equal(
            manifest.devDependencies?.[dependency],
            undefined,
            `${manifestPath} must not duplicate ${dependency}`
        );
    }
    assert.equal(
        manifest.eslintConfig,
        undefined,
        `${manifestPath} must not define a second active ESLint configuration`
    );
    if (fs.existsSync(path.join(workspace, "tsconfig.json"))) {
        assert.equal(
            manifest.devDependencies?.typescript,
            rootManifest.devDependencies.typescript.replace("^", ""),
            `${manifestPath} must declare the centralized TypeScript version exactly`
        );
    }
}

for (const command of ["format:check", "lint", "typecheck", "unit"]) {
    assert.ok(rootManifest.scripts[command], `Missing root ${command} command`);
}
for (const sourcePattern of [
    "scripts/**/*.mjs",
    "cli/bin/**/*.js",
    "website/**/*.js",
]) {
    assert.ok(
        rootManifest.scripts["format:check"].includes(sourcePattern),
        `Formatting must cover ${sourcePattern}`
    );
    assert.ok(
        rootManifest.scripts.lint.includes(sourcePattern),
        `Linting must cover ${sourcePattern}`
    );
}

function parsedProjectFiles(configPath) {
    const absoluteConfig = path.resolve(configPath);
    const read = ts.readConfigFile(absoluteConfig, ts.sys.readFile);
    if (read.error)
        throw new Error(
            ts.flattenDiagnosticMessageText(read.error.messageText, "\n")
        );
    const parsed = ts.parseJsonConfigFileContent(
        read.config,
        ts.sys,
        path.dirname(absoluteConfig),
        undefined,
        absoluteConfig
    );
    if (parsed.errors.length)
        throw new Error(
            parsed.errors
                .map((error) =>
                    ts.flattenDiagnosticMessageText(error.messageText, "\n")
                )
                .join("\n")
        );
    return new Set(parsed.fileNames.map((file) => path.resolve(file)));
}

for (const [configPath, requiredFiles] of [
    [
        "management-console/test/tsconfig.json",
        [
            "management-console/test/common/AuthService/index.ts",
            "management-console/test/components/DataFetcher/index.tsx",
        ],
    ],
    [
        "staticdeploy/test/tsconfig.json",
        [
            "staticdeploy/test/common/removeUndefs.ts",
            "staticdeploy/test/components/expressApp.ts",
        ],
    ],
    ["memory-storages/test/tsconfig.json", ["memory-storages/test/index.ts"]],
    ["pg-s3-storages/test/tsconfig.json", ["pg-s3-storages/test/index.ts"]],
]) {
    const files = parsedProjectFiles(configPath);
    for (const requiredFile of requiredFiles) {
        assert.ok(
            files.has(path.resolve(requiredFile)),
            `${configPath} must include ${requiredFile}`
        );
    }
}

const consoleManifest = JSON.parse(
    fs.readFileSync("management-console/package.json", "utf8")
);
assert.equal(
    consoleManifest.scripts.compile,
    "vite build",
    "The console compile command must use the supported Vite builder"
);
for (const retiredDependency of [
    "react-scripts",
    "enzyme",
    "oidc-client",
    "npm-run-all",
]) {
    assert.equal(
        consoleManifest.dependencies?.[retiredDependency] ??
            consoleManifest.devDependencies?.[retiredDependency],
        undefined,
        `The console must not retain ${retiredDependency}`
    );
}
assert.equal(rootManifest.workspaces.length, 13);
assert.equal(
    rootManifest.workspaces.includes("website"),
    false,
    "The retired website must remain outside the installable workspace graph"
);
const consoleIndex = fs.readFileSync("management-console/index.html", "utf8");
assert.match(
    consoleIndex,
    /<script\s+id="app-config"\s+src="\/app-config\.js"\s*><\/script>/,
    "The server-injected runtime configuration marker must remain intact"
);
assert.match(
    consoleIndex,
    /<script type="module" src="\/src\/index\.tsx"><\/script>/,
    "The Vite module entry must remain explicit"
);
const devConfig = fs.readFileSync(
    "management-console/public/app-config.js",
    "utf8"
);
assert.match(devConfig, /http:\/\/127\.0\.0\.1:3456/);
assert.match(devConfig, /http:\/\/127\.0\.0\.1:5173/);
assert.doesNotMatch(devConfig, /localhost/);
console.log("Central check contract covers all 13 retained workspaces.");
