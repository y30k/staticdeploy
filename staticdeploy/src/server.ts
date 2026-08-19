import { createServer, Server } from "node:http";

import { IStoragesModule } from "@staticdeploy/core";

import usecases from "./common/usecases";
import getAuthenticationStrategies from "./components/authenticationStrategies";
import getExpressApp from "./components/expressApp";
import getLogger from "./components/logger";
import getManagementRouter from "./components/managementRouter";
import getStoragesModule from "./components/storagesModule";
import V2SessionAuthenticationStrategy from "./components/V2SessionAuthenticationStrategy";
import getV2Sessions from "./components/v2Sessions";
import { APP_NAME, APP_VERSION, getConfig } from "./config";
import createRootUserAndGroup from "./init/createRootUserAndGroup";
import setupStorages from "./init/setupStorages";

const SHUTDOWN_TIMEOUT_MS = 10_000;
const SERVER_CLOSE_TIMEOUT_MS = 8_000;
const OUTPUT_DRAIN_TIMEOUT_MS = 1_000;

let logger = getLogger({
    appName: APP_NAME,
    appVersion: APP_VERSION,
    nodeEnv: process.env.NODE_ENV ?? "development",
    logLevel: "info",
});
let server: Server | undefined;
let oidcSessions: { destroy(): Promise<void> } | undefined;
let storagesModule:
    | (IStoragesModule & { destroy?: () => Promise<void> })
    | undefined;
let shutdownPromise: Promise<void> | undefined;
let shutdownRequested = false;

const flushOutput = async (): Promise<void> => {
    await new Promise<void>((resolve) => logger.flush(() => resolve()));
    await new Promise<void>((resolve) => {
        const timeout = setTimeout(resolve, OUTPUT_DRAIN_TIMEOUT_MS);
        process.stdout.write("", () => {
            clearTimeout(timeout);
            resolve();
        });
    });
};

const closeServer = async (): Promise<void> => {
    const activeServer = server;
    if (activeServer === undefined || !activeServer.listening) return;
    await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
            activeServer.closeAllConnections();
            reject(new Error("Timed out draining HTTP requests"));
        }, SERVER_CLOSE_TIMEOUT_MS);
        activeServer.close((error) => {
            clearTimeout(timeout);
            if (error) reject(error);
            else resolve();
        });
    });
};

const destroyStorages = async (): Promise<void> => {
    const results = await Promise.allSettled([
        storagesModule?.destroy?.(),
        oidcSessions?.destroy(),
    ]);
    const failure = results.find((result) => result.status === "rejected");
    if (failure?.status === "rejected") throw failure.reason;
};

const cleanupResources = async (): Promise<void> => {
    const failures: unknown[] = [];
    try {
        await closeServer();
    } catch (error) {
        failures.push(error);
    }
    try {
        await destroyStorages();
    } catch (error) {
        failures.push(error);
    }
    if (failures.length > 0) {
        const cleanupError = new Error("Resource cleanup failed") as Error & {
            errors: unknown[];
        };
        cleanupError.errors = failures;
        throw cleanupError;
    }
};

const withTimeout = async <T>(
    promise: Promise<T>,
    message: string
): Promise<T> =>
    new Promise<T>((resolve, reject) => {
        const timeout = setTimeout(
            () => reject(new Error(message)),
            SHUTDOWN_TIMEOUT_MS
        );
        void promise.then(
            (value) => {
                clearTimeout(timeout);
                resolve(value);
            },
            (error) => {
                clearTimeout(timeout);
                reject(error);
            }
        );
    });

const shutdown = (signal: "SIGINT" | "SIGTERM"): Promise<void> => {
    shutdownRequested = true;
    if (shutdownPromise !== undefined) return shutdownPromise;

    shutdownPromise = (async () => {
        logger.info({ signal }, "Server shutting down");
        let forceExit = false;
        try {
            await withTimeout(
                (async () => {
                    await startupPromise.catch(() => undefined);
                    await cleanupResources();
                })(),
                "Timed out shutting down service"
            );
            logger.info({ signal }, "Server shutdown complete");
        } catch (error) {
            forceExit = true;
            process.exitCode = 1;
            logger.fatal(error, "Server shutdown failed");
        }
        await flushOutput();
        if (forceExit) process.exit(1);
    })();
    return shutdownPromise;
};

process.on("SIGINT", () => {
    void shutdown("SIGINT");
});
process.on("SIGTERM", () => {
    void shutdown("SIGTERM");
});

const start = async (): Promise<void> => {
    try {
        const config = getConfig();
        logger = getLogger(config);

        const createdStoragesModule = getStoragesModule(config, logger);
        storagesModule = createdStoragesModule;
        const sessions = await getV2Sessions(config, logger);
        oidcSessions = sessions;
        const sessionAuthentication =
            sessions === undefined
                ? undefined
                : new V2SessionAuthenticationStrategy();
        const authenticationStrategies = getAuthenticationStrategies(
            config,
            logger,
            sessionAuthentication
        );
        const managementRouter = await getManagementRouter(
            config,
            sessions,
            sessionAuthentication
        );
        if (shutdownRequested) return;

        const expressApp = getExpressApp({
            config,
            authenticationStrategies,
            logger,
            managementRouter,
            storagesModule,
            usecases,
        });

        await setupStorages(storagesModule);
        await createRootUserAndGroup(config, storagesModule.getStorages());
        if (shutdownRequested) return;

        const createdServer = createServer().on("request", expressApp);
        server = createdServer;
        await new Promise<void>((resolve, reject) => {
            const onError = (error: Error): void => reject(error);
            createdServer.once("error", onError);
            createdServer.listen(config.port, () => {
                createdServer.removeListener("error", onError);
                resolve();
            });
        });
        if (shutdownRequested) return;

        createdServer.on("error", (error) =>
            logger.error(error, "HTTP server error")
        );
        logger.info(`Server listening on port ${config.port}`);
    } catch (error) {
        process.exitCode = 1;
        let forceExit = false;
        try {
            await withTimeout(
                cleanupResources(),
                "Timed out cleaning up failed startup"
            );
        } catch (cleanupError) {
            forceExit = true;
            logger.fatal(cleanupError, "Startup cleanup failed");
        }
        logger.fatal(error, "Error bootstrapping server");
        await flushOutput();
        if (forceExit) process.exit(1);
    }
};

const startupPromise = start();
