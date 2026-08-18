import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json")));
const projects = [];
const paths = {};
for (const workspace of manifest.workspaces) {
    const workspaceManifest = JSON.parse(
        fs.readFileSync(path.join(root, workspace, "package.json"))
    );
    if (!fs.existsSync(path.join(root, workspace, "tsconfig.json"))) continue;
    paths[workspaceManifest.name] = [`${workspace}/src/index.ts`];
    paths[`${workspaceManifest.name}/lib`] = [`${workspace}/src/index.ts`];
    paths[`${workspaceManifest.name}/lib/*`] = [`${workspace}/src/*`];
    paths[`${workspaceManifest.name}/*`] = [`${workspace}/src/*`];
}

function collectProjects(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        if (entry.name === "node_modules") continue;
        const entryPath = path.join(directory, entry.name);
        if (entry.isDirectory()) collectProjects(entryPath);
        else if (/^tsconfig(?:\.[^.]+)?\.json$/.test(entry.name)) {
            projects.push(path.relative(root, entryPath));
        }
    }
}

for (const workspace of manifest.workspaces)
    collectProjects(path.join(root, workspace));
projects.sort();

const typedWorkspaces = new Set(
    projects.map((project) => project.split(path.sep)[0])
);
if (typedWorkspaces.size !== 13 || projects.length !== 28) {
    throw new Error(
        `Expected 28 TypeScript projects across 13 workspaces; found ${projects.length} projects across ${typedWorkspaces.size} workspaces`
    );
}

let tempDirectory;
let failureStatus;
try {
    tempDirectory = fs.mkdtempSync(path.join(root, ".typecheck-"));
    const workspaceDeclarations = path.join(tempDirectory, "workspaces.d.ts");
    fs.writeFileSync(
        workspaceDeclarations,
        '/// <reference types="mocha" />\n'
    );
    for (const [index, project] of projects.entries()) {
        console.log(`Typechecking ${project}`);
        const typecheckProject = path.join(tempDirectory, `${index}.json`);
        fs.writeFileSync(
            typecheckProject,
            JSON.stringify({
                extends: path.join(root, project),
                files: [workspaceDeclarations],
                compilerOptions: {
                    baseUrl: root,
                    // Source aliases make the check independent of compiled
                    // output. Compile separately enforces emitter-only options.
                    isolatedModules: false,
                    noEmit: true,
                    paths,
                },
            })
        );
        const result = spawnSync(
            process.execPath,
            [
                path.join(root, "node_modules/typescript/bin/tsc"),
                "--project",
                typecheckProject,
            ],
            { stdio: "inherit" }
        );
        if (result.status !== 0) {
            failureStatus = result.status ?? 1;
            break;
        }
    }
} finally {
    if (tempDirectory)
        fs.rmSync(tempDirectory, { recursive: true, force: true });
}

if (failureStatus) process.exitCode = failureStatus;
else
    console.log(
        `Typechecked ${projects.length} projects across ${typedWorkspaces.size} TypeScript workspaces without emitting.`
    );
