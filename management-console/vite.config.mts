import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
    base: "./",
    plugins: [react()],
    resolve: {
        alias: {
            "@staticdeploy/core/browser": fileURLToPath(
                new URL("../core/src/browser.ts", import.meta.url)
            ),
            "@staticdeploy/core": fileURLToPath(
                new URL("../core/src/index.ts", import.meta.url)
            ),
            "@staticdeploy/sdk": fileURLToPath(
                new URL("../sdk/src/index.ts", import.meta.url)
            ),
        },
    },
    server: {
        host: "127.0.0.1",
    },
    build: {
        outDir: "build",
        emptyOutDir: true,
    },
    test: {
        environment: "jsdom",
        globals: true,
        setupFiles: ["./test/setup.ts"],
        include: ["test/**/*.ts", "test/**/*.tsx"],
        exclude: ["test/setup.ts"],
        css: true,
        clearMocks: true,
    },
});
