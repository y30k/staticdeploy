import express, { RequestHandler } from "express";
import { readdir } from "node:fs/promises";
import { extname, relative, resolve, sep } from "node:path";

import { DEV_ORIGIN, MOCK_HOST, MOCK_PORT } from "./oidc/state";

const root = __dirname;
const methods = new Set(["delete", "get", "patch", "post", "put"]);

async function routeFiles(directory: string): Promise<string[]> {
    const entries = await readdir(directory, { withFileTypes: true });
    const files = await Promise.all(
        entries.map(async (entry) => {
            const path = resolve(directory, entry.name);
            if (entry.isDirectory()) return routeFiles(path);
            const method = entry.name.replace(/\.ts$/, "").toLowerCase();
            return extname(entry.name) === ".ts" && methods.has(method)
                ? [path]
                : [];
        })
    );
    return files.flat().sort();
}

function routeFor(file: string) {
    const segments = relative(root, file).split(sep);
    const method = segments.pop()!.replace(/\.ts$/, "").toLowerCase();
    if (!methods.has(method))
        throw new Error(`Unsupported mock method: ${file}`);
    const route =
        "/" +
        segments
            .map((segment) => segment.replace(/^\{(.+)\}$/, ":$1"))
            .join("/");
    return { method, route };
}

export async function createMockApp() {
    const app = express();
    app.use(express.json({ limit: "1mb" }));
    app.use(express.urlencoded({ extended: false, limit: "16kb" }));
    app.use((req, res, next) => {
        const origin = req.get("origin");
        if (origin === DEV_ORIGIN) {
            res.setHeader("access-control-allow-origin", DEV_ORIGIN);
            res.setHeader("access-control-allow-credentials", "true");
            res.setHeader("vary", "Origin");
            res.setHeader(
                "access-control-allow-headers",
                "authorization, content-type"
            );
            res.setHeader(
                "access-control-allow-methods",
                "DELETE, GET, OPTIONS, PATCH, POST, PUT"
            );
        }
        if (req.method === "OPTIONS") {
            res.sendStatus(origin === DEV_ORIGIN ? 204 : 403);
            return;
        }
        setTimeout(next, 100);
    });

    for (const file of await routeFiles(root)) {
        const { method, route } = routeFor(file);
        const module = await import(file);
        const handler = module.default as RequestHandler;
        switch (method) {
            case "delete":
                app.delete(route, handler);
                break;
            case "get":
                app.get(route, handler);
                break;
            case "patch":
                app.patch(route, handler);
                break;
            case "post":
                app.post(route, handler);
                break;
            case "put":
                app.put(route, handler);
                break;
        }
    }
    return app;
}

async function main() {
    const app = await createMockApp();
    app.listen(MOCK_PORT, MOCK_HOST, () => {
        process.stdout.write(
            `Management console mock API listening on http://${MOCK_HOST}:${MOCK_PORT}\n`
        );
    });
}

if (process.env.NODE_ENV !== "test") {
    main().catch((error) => {
        process.stderr.write(
            `${error instanceof Error ? error.stack : error}\n`
        );
        process.exitCode = 1;
    });
}
