import { IncomingMessage, ServerResponse } from "node:http";

export const REDACTED_VALUE = "[Redacted]";
const CIRCULAR_VALUE = "[Circular]";

const normalizeKey = (key: string): string =>
    key.toLowerCase().replace(/[^a-z0-9]/g, "");

const isSensitiveKey = (key: string): boolean => {
    const normalized = normalizeKey(key);
    return (
        normalized.includes("authorization") ||
        normalized.includes("proxyauth") ||
        normalized.includes("cookie") ||
        normalized.includes("credential") ||
        normalized.includes("password") ||
        normalized.includes("passwd") ||
        normalized.includes("token") ||
        normalized.includes("apikey") ||
        normalized.includes("secret") ||
        normalized.includes("privatekey")
    );
};

const sanitizeError = (
    error: Error,
    seen: WeakSet<object>
): Record<string, unknown> | string => {
    if (seen.has(error)) return CIRCULAR_VALUE;
    seen.add(error);

    const sanitized: Record<string, unknown> = {
        type: error.constructor.name,
        message: error.message,
        stack: error.stack,
    };

    const errorWithDetails = error as Error & {
        cause?: unknown;
        errors?: unknown;
    };
    if ("cause" in errorWithDetails) {
        sanitized.cause = sanitizeLogValue(errorWithDetails.cause, seen);
    }
    if ("errors" in errorWithDetails) {
        sanitized.errors = sanitizeLogValue(errorWithDetails.errors, seen);
    }

    for (const key of Object.keys(error)) {
        if (key === "cause" || key === "errors") continue;
        sanitized[key] = isSensitiveKey(key)
            ? REDACTED_VALUE
            : sanitizeLogValue(
                  (error as unknown as Record<string, unknown>)[key],
                  seen
              );
    }
    return sanitized;
};

export const sanitizeLogValue = (
    value: unknown,
    seen = new WeakSet<object>()
): unknown => {
    if (value === null || typeof value !== "object") return value;
    if (value instanceof IncomingMessage) return serializeHttpRequest(value);
    if (value instanceof ServerResponse) return serializeHttpResponse(value);
    if (value instanceof Error) return sanitizeError(value, seen);
    if (Buffer.isBuffer(value) || value instanceof Date) return value;
    if (Array.isArray(value)) {
        if (seen.has(value)) return CIRCULAR_VALUE;
        seen.add(value);
        return value.map((entry) => sanitizeLogValue(entry, seen));
    }

    if (seen.has(value)) return CIRCULAR_VALUE;
    seen.add(value);

    const sanitized: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
        sanitized[key] = isSensitiveKey(key)
            ? REDACTED_VALUE
            : sanitizeLogValue((value as Record<string, unknown>)[key], seen);
    }
    return sanitized;
};

interface ISerializedRequestLike {
    raw?: unknown;
    id?: unknown;
    method?: string;
    url?: string;
    headers?: Record<string, unknown>;
    remoteAddress?: string;
    remotePort?: number;
}

interface ISerializedResponseLike {
    raw?: unknown;
    statusCode?: number | null;
    headers?: Record<string, unknown>;
}

export const serializeHttpRequest = (
    value: IncomingMessage | ISerializedRequestLike
): Record<string, unknown> => {
    const raw =
        value instanceof IncomingMessage
            ? value
            : value.raw instanceof IncomingMessage
              ? value.raw
              : undefined;
    const serialized = value as ISerializedRequestLike;
    const headers = Object.fromEntries(
        Object.entries(raw?.headers ?? serialized.headers ?? {}).filter(
            ([name]) => normalizeKey(name) !== "xrequestid"
        )
    );
    return {
        id: serialized.id,
        method: raw?.method ?? serialized.method,
        url: stripUrlQueryAndHash(raw?.url ?? serialized.url ?? ""),
        headers: sanitizeLogValue(headers),
        remoteAddress: serialized.remoteAddress ?? raw?.socket.remoteAddress,
        remotePort: serialized.remotePort ?? raw?.socket.remotePort,
    };
};

export const serializeHttpResponse = (
    value: ServerResponse | ISerializedResponseLike
): Record<string, unknown> => {
    const raw =
        value instanceof ServerResponse
            ? value
            : value.raw instanceof ServerResponse
              ? value.raw
              : undefined;
    const serialized = value as ISerializedResponseLike;
    return {
        statusCode:
            raw !== undefined && !raw.writableEnded
                ? null
                : (raw?.statusCode ?? serialized.statusCode ?? null),
        headers: sanitizeLogValue(
            raw?.getHeaders() ?? serialized.headers ?? {}
        ),
    };
};

export const stripUrlQueryAndHash = (url: string): string => {
    const queryIndex = url.indexOf("?");
    const hashIndex = url.indexOf("#");
    const end = Math.min(
        queryIndex === -1 ? url.length : queryIndex,
        hashIndex === -1 ? url.length : hashIndex
    );
    return url.slice(0, end);
};
