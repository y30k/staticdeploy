export type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal";

export default interface IConfig {
    // General service configurations
    appName: string;
    appVersion: string;
    nodeEnv: string;
    logLevel: LogLevel;
    port: string;
    managementHostname: string;
    enableManagementEndpoints: boolean;
    maxRequestBodySize: string;

    // Routing configuration
    hostnameHeader?: string;

    // Auth configurations
    enforceAuth: boolean;
    createRootUser: boolean;
    jwtSecretOrPublicKey?: Buffer;
    jwtAlgorithm?: "HS256" | "RS256";
    oidcConfigurationUrl?: string;
    oidcClientId?: string;
    oidcProviderName?: string;

    // pg-s3-storages configurations
    postgresUrl?: string;
    s3Bucket?: string;
    s3Endpoint?: string;
    s3Region?: string;
    s3ForcePathStyle?: boolean;
    s3AccessKeyId?: string;
    s3SecretAccessKey?: string;
    s3EnableGCSCompatibility?: boolean;
}
