import env from "@mondora/env";

import IConfig, { LogLevel } from "./common/IConfig";

const pkg = require("../package.json");

export const APP_NAME: string = pkg.name;
export const APP_VERSION: string = pkg.version;

const LOG_LEVELS: LogLevel[] = [
    "trace",
    "debug",
    "info",
    "warn",
    "error",
    "fatal",
];

export const parseSessionEncryptionKeys = (
    value: string
): Array<{ id: string; key: Buffer }> => {
    let parsed: unknown;
    try {
        parsed = JSON.parse(value);
    } catch {
        throw new Error("OIDC_SESSION_ENCRYPTION_KEYS must be valid JSON");
    }
    if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 8)
        throw new Error(
            "OIDC_SESSION_ENCRYPTION_KEYS must contain one to eight keys"
        );
    return parsed.map((candidate) => {
        if (
            candidate === null ||
            typeof candidate !== "object" ||
            !("id" in candidate) ||
            !("key" in candidate) ||
            typeof candidate.id !== "string" ||
            typeof candidate.key !== "string"
        )
            throw new Error(
                "OIDC_SESSION_ENCRYPTION_KEYS contains an invalid key"
            );
        const key = Buffer.from(candidate.key, "base64");
        if (key.length !== 32 || key.toString("base64") !== candidate.key)
            throw new Error(
                "OIDC session encryption keys must be canonical base64 32-byte values"
            );
        return { id: candidate.id, key };
    });
};

export const parseLogLevel = (value: string): LogLevel => {
    const level = LOG_LEVELS.find((candidate) => candidate === value);
    if (level === undefined) {
        throw new Error(`LOG_LEVEL must be one of ${LOG_LEVELS.join(", ")}`);
    }
    return level;
};

export const getConfig = (): IConfig => ({
    // General service configurations
    appName: APP_NAME,
    appVersion: APP_VERSION,
    nodeEnv: env("NODE_ENV", { default: "development" }),
    logLevel: parseLogLevel(env("LOG_LEVEL", { default: "info" })),
    port: env("PORT", { default: "3000" }),
    managementHostname: env("MANAGEMENT_HOSTNAME", {
        required: true,
        nonProductionDefault: "localhost",
    }),
    enableManagementEndpoints: env("ENABLE_MANAGEMENT_ENDPOINTS", {
        default: "true",
        parse: (value) => value !== "false",
    }),
    maxRequestBodySize: env("MAX_REQUEST_BODY_SIZE", { default: "100mb" }),

    // Routing configuration
    hostnameHeader: env("HOSTNAME_HEADER"),

    // Auth configurations
    enforceAuth: env("ENFORCE_AUTH", {
        default: "true",
        parse: (value) => value !== "false",
    }),
    createRootUser: env("CREATE_ROOT_USER", {
        default: "true",
        parse: (value) => value !== "false",
    }),
    jwtSecretOrPublicKey: env("JWT_SECRET_OR_PUBLIC_KEY", {
        parse: (value) => Buffer.from(value, "base64"),
    }),
    jwtAlgorithm: env("JWT_ALGORITHM", {
        parse: (value) => {
            if (value !== "HS256" && value !== "RS256") {
                throw new Error("JWT_ALGORITHM must be HS256 or RS256");
            }
            return value;
        },
    }),
    oidcConfigurationUrl: env("OIDC_CONFIGURATION_URL"),
    oidcClientId: env("OIDC_CLIENT_ID"),
    oidcProviderName: env("OIDC_PROVIDER_NAME"),
    oidcExpectedIssuer: env("OIDC_EXPECTED_ISSUER"),
    oidcRedirectUri: env("OIDC_REDIRECT_URI"),
    portalOrigin: env("PORTAL_ORIGIN"),
    oidcSessionPrimaryKeyId: env("OIDC_SESSION_PRIMARY_KEY_ID"),
    oidcSessionEncryptionKeys: env("OIDC_SESSION_ENCRYPTION_KEYS", {
        parse: parseSessionEncryptionKeys,
    }),
    oidcPostgresUrl: env("OIDC_POSTGRES_URL"),
    oidcAllowHttpLoopbackForTests: env("OIDC_ALLOW_HTTP_LOOPBACK_FOR_TESTS", {
        default: "false",
        parse: (value) => value === "true",
    }),

    // pg-s3-storages configurations
    postgresUrl: env("POSTGRES_URL"),
    s3Bucket: env("S3_BUCKET"),
    s3Endpoint: env("S3_ENDPOINT"),
    s3Region: env("S3_REGION", { default: "us-east-1" }),
    s3ForcePathStyle: env("S3_FORCE_PATH_STYLE", {
        default: "true",
        parse: (value) => value !== "false",
    }),
    s3AccessKeyId: env("S3_ACCESS_KEY_ID"),
    s3SecretAccessKey: env("S3_SECRET_ACCESS_KEY"),
    s3EnableGCSCompatibility: env("S3_ENABLE_GCS_COMPATIBILITY", {
        default: "false",
        parse: (value) => value === "true",
    }),
});
