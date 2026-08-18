import { IAuthenticationStrategy, IIdpUser } from "@staticdeploy/core";
import axios, { AxiosRequestConfig } from "axios";
import { createLocalJWKSet, JSONWebKeySet, jwtVerify } from "jose";

export interface ILogger {
    error(error: unknown, message: string): void;
}

interface IOpenidConfiguration {
    issuer: string;
    jwks_uri: string;
}

interface IConfiguredStrategy {
    openidConfiguration: IOpenidConfiguration;
    keySet: ReturnType<typeof createLocalJWKSet>;
}

const HTTP_TIMEOUT_MS = 5000;
const HTTP_MAX_CONTENT_LENGTH = 1024 * 1024;
const CONFIGURATION_CACHE_MAX_AGE_MS = 5 * 60 * 1000;
const HTTP_REQUEST_OPTIONS: AxiosRequestConfig = {
    timeout: HTTP_TIMEOUT_MS,
    maxContentLength: HTTP_MAX_CONTENT_LENGTH,
    maxBodyLength: HTTP_MAX_CONTENT_LENGTH,
    maxRedirects: 0,
    responseType: "json",
    transitional: { silentJSONParsing: false },
};

const assertHttpUrl = (value: unknown, field: string): string => {
    if (typeof value !== "string") {
        throw new TypeError(`${field} must be an HTTP(S) URL`);
    }
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        throw new TypeError(`${field} must be an HTTP(S) URL`);
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new TypeError(`${field} must be an HTTP(S) URL`);
    }
    return value;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === "object" && value !== null && !Array.isArray(value);

export default class OidcAuthenticationStrategy
    implements IAuthenticationStrategy
{
    private configurationPromise?: Promise<IConfiguredStrategy>;
    private configurationExpiresAt?: number;

    constructor(
        private openidConfigurationUrl: string,
        private clientId: string,
        private logger: ILogger
    ) {}

    async getIdpUserFromAuthToken(authToken: string): Promise<IIdpUser | null> {
        let configuredStrategy: IConfiguredStrategy;
        try {
            configuredStrategy = await this.configureStrategy();
        } catch {
            return null;
        }

        try {
            const { payload } = await jwtVerify(
                authToken,
                configuredStrategy.keySet,
                {
                    issuer: configuredStrategy.openidConfiguration.issuer,
                    audience: this.clientId,
                    algorithms: ["RS256"],
                    requiredClaims: ["iss", "aud", "sub", "exp"],
                }
            );
            return typeof payload.iss === "string" &&
                typeof payload.sub === "string"
                ? { idp: payload.iss, id: payload.sub }
                : null;
        } catch (err) {
            this.logger.error(
                err,
                "Error verifying token with OidcAuthenticationStrategy"
            );
            return null;
        }
    }

    private async configureStrategy(): Promise<IConfiguredStrategy> {
        if (
            this.configurationPromise &&
            (this.configurationExpiresAt === undefined ||
                Date.now() < this.configurationExpiresAt)
        ) {
            return this.configurationPromise;
        }

        const configurationPromise = this.fetchConfiguration();
        this.configurationPromise = configurationPromise;
        this.configurationExpiresAt = undefined;

        try {
            const configuredStrategy = await configurationPromise;
            if (this.configurationPromise === configurationPromise) {
                this.configurationExpiresAt =
                    Date.now() + CONFIGURATION_CACHE_MAX_AGE_MS;
            }
            return configuredStrategy;
        } catch (err) {
            if (this.configurationPromise === configurationPromise) {
                this.configurationPromise = undefined;
                this.configurationExpiresAt = undefined;
            }
            this.logger.error(
                err,
                "Error configuring OidcAuthenticationStrategy"
            );
            throw err;
        }
    }

    private async fetchConfiguration(): Promise<IConfiguredStrategy> {
        const openidConfiguration = await this.fetchOpenidConfiguration();
        const keySet = await this.fetchJwks(openidConfiguration.jwks_uri);
        return { openidConfiguration, keySet };
    }

    private async fetchOpenidConfiguration(): Promise<IOpenidConfiguration> {
        const url = assertHttpUrl(
            this.openidConfigurationUrl,
            "openidConfigurationUrl"
        );
        const { data } = await axios.get<unknown>(url, HTTP_REQUEST_OPTIONS);
        if (!isRecord(data)) {
            throw new TypeError("Invalid OpenID configuration response");
        }
        return {
            issuer: assertHttpUrl(data.issuer, "issuer"),
            jwks_uri: assertHttpUrl(data.jwks_uri, "jwks_uri"),
        };
    }

    private async fetchJwks(
        url: string
    ): Promise<ReturnType<typeof createLocalJWKSet>> {
        const { data } = await axios.get<unknown>(url, HTTP_REQUEST_OPTIONS);
        if (!isRecord(data) || !Array.isArray(data.keys)) {
            throw new TypeError("Invalid JWKS response");
        }
        return createLocalJWKSet(data as unknown as JSONWebKeySet);
    }
}
