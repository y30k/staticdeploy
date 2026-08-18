import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import {
    createConnection,
    createServer as createNetServer,
    Socket,
} from "node:net";
import path from "node:path";

const serviceDirectory = process.cwd();
const tsNodeRegister = path.resolve(
    serviceDirectory,
    "../node_modules/ts-node/register"
);

const spawnService = (
    environment: Record<string, string>
): {
    child: ChildProcessWithoutNullStreams;
    stderr: () => string;
    stdout: () => string;
} => {
    let stdout = "";
    let stderr = "";
    const child = spawn(
        process.execPath,
        ["-r", tsNodeRegister, "src/server.ts"],
        {
            cwd: serviceDirectory,
            env: {
                PATH: process.env.PATH ?? "",
                NODE_ENV: "production",
                TS_NODE_FILES: "true",
                MANAGEMENT_HOSTNAME: "localhost",
                ENABLE_MANAGEMENT_ENDPOINTS: "false",
                ENFORCE_AUTH: "false",
                CREATE_ROOT_USER: "false",
                PORT: "0",
                LOG_LEVEL: "info",
                ...environment,
            },
            stdio: "pipe",
        }
    );
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
        stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
        stderr += chunk;
    });
    return { child, stdout: () => stdout, stderr: () => stderr };
};

const waitFor = async (
    predicate: () => boolean,
    description: string
): Promise<void> => {
    for (let attempt = 0; attempt < 400; attempt += 1) {
        if (predicate()) return;
        await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.fail(`Timed out waiting for ${description}`);
};

const waitForExit = (
    child: ChildProcessWithoutNullStreams
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> =>
    new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            child.kill("SIGKILL");
            reject(new Error("Timed out waiting for service process to exit"));
        }, 15_000);
        child.once("exit", (code, signal) => {
            clearTimeout(timeout);
            resolve({ code, signal });
        });
    });

const reservePort = async (): Promise<number> => {
    const reservation = createNetServer();
    await new Promise<void>((resolve) => reservation.listen(0, resolve));
    const address = reservation.address();
    assert.ok(address && typeof address === "object");
    const port = address.port;
    await new Promise<void>((resolve, reject) =>
        reservation.close((error) => (error ? reject(error) : resolve()))
    );
    return port;
};

const openIncompleteRequest = async (port: number): Promise<Socket> => {
    const socket = createConnection({ host: "127.0.0.1", port });
    await new Promise<void>((resolve, reject) => {
        socket.once("connect", resolve);
        socket.once("error", reject);
    });
    socket.write(
        "POST /api/apps HTTP/1.1\r\n" +
            "Host: localhost\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: 100000\r\n\r\n{"
    );
    return socket;
};

const parseJsonLines = (output: string): Array<Record<string, any>> =>
    output
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line));

describe("service process logging and shutdown", () => {
    it("captures a final structured startup error for invalid LOG_LEVEL", async () => {
        const service = spawnService({ LOG_LEVEL: "verbose" });
        const result = await waitForExit(service.child);

        assert.deepEqual(result, { code: 1, signal: null });
        const records = parseJsonLines(service.stdout());
        const finalRecord = records[records.length - 1];
        assert.equal(finalRecord?.level, 60);
        assert.equal(finalRecord?.msg, "Error bootstrapping server");
        assert.match(finalRecord?.err.message, /LOG_LEVEL must be one of/);
        assert.equal(typeof finalRecord?.err.stack, "string");
        assert.equal(service.stderr(), "");
    });

    it("captures a post-configuration startup failure at LOG_LEVEL=fatal", async () => {
        const service = spawnService({
            LOG_LEVEL: "fatal",
            JWT_SECRET_OR_PUBLIC_KEY: Buffer.from("secret").toString("base64"),
        });
        const result = await waitForExit(service.child);

        assert.deepEqual(result, { code: 1, signal: null });
        const records = parseJsonLines(service.stdout());
        const finalRecord = records[records.length - 1];
        assert.equal(finalRecord?.level, 60);
        assert.equal(finalRecord?.msg, "Error bootstrapping server");
        assert.match(finalRecord?.err.message, /JWT_ALGORITHM is required/);
        assert.equal(service.stderr(), "");
    });

    it("drains the final fatal JSON record before forcing exit on a stuck request", async () => {
        const port = await reservePort();
        const service = spawnService({
            PORT: port.toString(),
            ENABLE_MANAGEMENT_ENDPOINTS: "true",
        });
        let socket: Socket | undefined;
        try {
            await waitFor(
                () => service.stdout().includes("Server listening on port"),
                "service startup log"
            );
            socket = await openIncompleteRequest(port);
            assert.equal(service.child.kill("SIGTERM"), true);
            const result = await waitForExit(service.child);

            assert.deepEqual(result, { code: 1, signal: null });
            const records = parseJsonLines(service.stdout());
            const finalRecord = records[records.length - 1];
            assert.equal(finalRecord?.level, 60);
            assert.equal(finalRecord?.msg, "Server shutdown failed");
            assert.match(
                finalRecord?.err.errors[0].message,
                /Timed out draining HTTP requests/
            );
            assert.equal(service.stdout().endsWith("\n"), true);
            assert.equal(service.stderr(), "");
        } finally {
            socket?.destroy();
            if (service.child.exitCode === null) service.child.kill("SIGKILL");
        }
    });

    it("captures one complete structured shutdown sequence across repeated signals", async () => {
        const service = spawnService({});
        try {
            await waitFor(
                () => service.stdout().includes("Server listening on port"),
                "service startup log"
            );

            assert.equal(service.child.kill("SIGTERM"), true);
            service.child.kill("SIGINT");
            const result = await waitForExit(service.child);

            assert.deepEqual(result, { code: 0, signal: null });
            const records = parseJsonLines(service.stdout());
            const shuttingDown = records.filter(
                ({ msg }) => msg === "Server shutting down"
            );
            const shutdownComplete = records.filter(
                ({ msg }) => msg === "Server shutdown complete"
            );
            assert.equal(shuttingDown.length, 1);
            assert.equal(shutdownComplete.length, 1);
            assert.ok(["SIGINT", "SIGTERM"].includes(shuttingDown[0].signal));
            assert.equal(shutdownComplete[0].signal, shuttingDown[0].signal);
            assert.equal(
                records[records.length - 1]?.msg,
                "Server shutdown complete"
            );
            assert.equal(service.stderr(), "");
        } finally {
            if (service.child.exitCode === null) service.child.kill("SIGKILL");
        }
    });
});
