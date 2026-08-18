import { hostname } from "node:os";

import pino, { DestinationStream, Logger } from "pino";

import IConfig from "../common/IConfig";
import {
    REDACTED_VALUE,
    sanitizeLogValue,
    serializeHttpRequest,
    serializeHttpResponse,
} from "../common/sanitizeLogValue";

export { REDACTED_VALUE };

export const serializeError = (value: unknown): unknown => {
    if (value !== null && typeof value === "object" && "raw" in value) {
        return sanitizeLogValue((value as { raw: unknown }).raw);
    }
    return sanitizeLogValue(value);
};

const sanitizeLogArgument = (argument: unknown): unknown => {
    if (argument instanceof Error) return argument;
    if (
        argument !== null &&
        typeof argument === "object" &&
        !Array.isArray(argument) &&
        Object.getPrototypeOf(argument) === Object.prototype
    ) {
        const remaining = { ...(argument as Record<string, unknown>) };
        const serializerInputs: Record<string, unknown> = {};
        for (const key of ["err", "req", "res"]) {
            if (key in remaining) {
                serializerInputs[key] = remaining[key];
                delete remaining[key];
            }
        }
        return {
            ...(sanitizeLogValue(remaining) as Record<string, unknown>),
            ...serializerInputs,
        };
    }
    return sanitizeLogValue(argument);
};

type LoggerConfig = Pick<
    IConfig,
    "appName" | "appVersion" | "nodeEnv" | "logLevel"
>;

export default (
    config: LoggerConfig,
    stream: DestinationStream = process.stdout
): Logger =>
    pino(
        {
            name: config.appName,
            level: config.nodeEnv === "test" ? "silent" : config.logLevel,
            base: {
                pid: process.pid,
                hostname: hostname(),
                version: config.appVersion,
            },
            serializers: {
                err: serializeError,
                req: serializeHttpRequest,
                res: serializeHttpResponse,
            },
            hooks: {
                logMethod(args, method) {
                    method.apply(this, args.map(sanitizeLogArgument));
                },
            },
        },
        stream
    );
