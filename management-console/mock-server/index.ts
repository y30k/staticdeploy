import express, { RequestHandler } from "express";
import { readdir } from "node:fs/promises";
import { extname, relative, resolve, sep } from "node:path";

const host = "127.0.0.1";
const port = 3456;
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

async function main() {
    const app = express();
    app.use(express.json({ limit: "1mb" }));
    app.use((_req, res, next) => {
        res.setHeader("access-control-allow-origin", "http://127.0.0.1:5173");
        res.setHeader(
            "access-control-allow-headers",
            "authorization, content-type"
        );
        res.setHeader(
            "access-control-allow-methods",
            "DELETE, GET, PATCH, POST, PUT"
        );
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

    app.listen(port, host, () => {
        process.stdout.write(
            `Management console mock API listening on http://${host}:${port}\n`
        );
    });
}

main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : error}\n`);
    process.exitCode = 1;
});
