import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
    base: "/",
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
        port: 5173,
        strictPort: true,
    },
    build: {
        outDir: "build",
        emptyOutDir: true,
    },
    test: {
        environment: "jsdom",
        environmentOptions: {
            jsdom: {
                url: "http://127.0.0.1:5173/",
            },
        },
        globals: true,
        setupFiles: ["./test/setup.ts"],
        include: ["test/**/*.ts", "test/**/*.tsx"],
        exclude: ["test/setup.ts"],
        css: true,
        clearMocks: true,
        coverage: {
            provider: "v8",
            include: ["src/**/*.{ts,tsx}"],
            exclude: ["src/**/*.d.ts"],
            reportsDirectory: "coverage",
            reporter: ["text-summary", "json", "lcov"],
        },
    },
});
