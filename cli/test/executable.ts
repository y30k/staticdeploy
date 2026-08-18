import { expect } from "chai";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const executablePath = resolve(process.cwd(), "bin/staticdeploy.js");

function runCli(args: string[]) {
    return spawnSync(process.execPath, [executablePath, ...args], {
        encoding: "utf8",
        env: { ...process.env, FORCE_COLOR: "0" },
    });
}

describe("staticdeploy executable", () => {
    it("prints help and exits successfully", () => {
        const result = runCli(["--help"]);

        expect(result.status).to.equal(0);
        expect(result.signal).to.equal(null);
        expect(result.stdout).to.contain("Usage:");
        expect(result.stdout).to.contain("bundle");
        expect(result.stdout).to.contain("deploy");
        expect(result.stderr).to.equal("");
    });

    it("rejects an unknown option with a nonzero exit", () => {
        const result = runCli([
            "bundle",
            "--apiUrl",
            "http://localhost",
            "--from",
            ".",
            "--name",
            "name",
            "--tag",
            "tag",
            "--description",
            "description",
            "--definitely-unknown",
        ]);
        const output = `${result.stdout}${result.stderr}`;

        expect(result.status).to.equal(1);
        expect(result.signal).to.equal(null);
        expect(output).to.contain("Unknown arguments:");
        expect(output).to.contain("definitely-unknown");
    });

    it("requires a command with a nonzero exit", () => {
        const result = runCli([]);
        const output = `${result.stdout}${result.stderr}`;

        expect(result.status).to.equal(1);
        expect(result.signal).to.equal(null);
        expect(output).to.contain(
            "Not enough non-option arguments: got 0, need at least 1"
        );
    });
});
