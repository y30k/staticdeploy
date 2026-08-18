import { JSONWebKeySet, JWKS, JWT } from "@panva/jose";
import { IAuthenticationStrategy, IIdpUser } from "@staticdeploy/core";
import axios, { AxiosRequestConfig } from "axios";
import Logger from "bunyan";
import mem from "mem";

interface IOpenidConfiguration {
    issuer: string;
    jwks_uri: string;
}

const HTTP_TIMEOUT_MS = 5000;
const HTTP_MAX_CONTENT_LENGTH = 1024 * 1024;
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
    private openidConfiguration!: IOpenidConfiguration;
    private keyStore!: JWKS.KeyStore;

    constructor(
        private openidConfigurationUrl: string,
        private clientId: string,
        private logger: Logger
    ) {}

    async getIdpUserFromAuthToken(authToken: string): Promise<IIdpUser | null> {
        try {
            await this.configureStrategy();
        } catch {
            return null;
        }

        try {
            const jwt = JWT.IdToken.verify(authToken, this.keyStore, {
                issuer: this.openidConfiguration.issuer,
                audience: this.clientId,
            }) as { sub: string; iss: string };
            return { idp: jwt.iss, id: jwt.sub };
        } catch (err) {
            this.logger.error(
                err,
                "Error verifying token with OidcAuthenticationStrategy"
            );
            return null;
        }
    }

    private configureStrategy = mem(
        async () => {
            try {
                const openidConfiguration =
                    await this.fetchOpenidConfiguration();
                const keyStore = await this.fetchJwks(
                    openidConfiguration.jwks_uri
                );
                this.openidConfiguration = openidConfiguration;
                this.keyStore = keyStore;
            } catch (err) {
                // mem caches rejected promises, so explicitly evict failures to
                // allow a later authentication attempt to retry configuration.
                mem.clear(this.configureStrategy);
                this.logger.error(
                    err,
                    "Error configuring OidcAuthenticationStrategy"
                );
                throw err;
            }
        },
        { maxAge: 5 * 60 * 1000 }
    );

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

    private async fetchJwks(url: string): Promise<JWKS.KeyStore> {
        const { data } = await axios.get<unknown>(url, HTTP_REQUEST_OPTIONS);
        if (!isRecord(data) || !Array.isArray(data.keys)) {
            throw new TypeError("Invalid JWKS response");
        }
        return JWKS.asKeyStore(data as unknown as JSONWebKeySet);
    }
}
