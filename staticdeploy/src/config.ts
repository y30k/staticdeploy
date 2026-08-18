import env from "@mondora/env";
import { LogLevelString } from "bunyan";

import IConfig from "./common/IConfig";

const pkg = require("../package.json");

const config: IConfig = {
    // General service configurations
    appName: pkg.name,
    appVersion: pkg.version,
    nodeEnv: env("NODE_ENV", { default: "development" }),
    logLevel: env("LOG_LEVEL", { default: "info" }) as LogLevelString,
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
};
export default config;
