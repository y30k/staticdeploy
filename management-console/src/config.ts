interface AppConfig {
    API_URL?: string;
    AUTH_ENFORCED?: string;
    JWT_ENABLED?: string;
    OIDC_CLIENT_ID?: string;
    OIDC_CONFIGURATION_URL?: string;
    OIDC_ENABLED?: string;
    OIDC_PROVIDER_NAME?: string;
    OIDC_REDIRECT_URL?: string;
}

const APP_CONFIG =
    (window as Window & { APP_CONFIG?: AppConfig }).APP_CONFIG ?? {};

export default {
    // StaticdeployClient
    apiUrl: APP_CONFIG.API_URL || "http://127.0.0.1:3456",
    // General auth
    authEnforced: APP_CONFIG.AUTH_ENFORCED === "true",
    // OIDC auth strategy
    oidcEnabled: APP_CONFIG.OIDC_ENABLED === "true",
    oidcConfigurationUrl:
        APP_CONFIG.OIDC_CONFIGURATION_URL ||
        "http://127.0.0.1:3456/oidc/configuration",
    oidcClientId: APP_CONFIG.OIDC_CLIENT_ID || "clientId",
    oidcRedirectUrl: APP_CONFIG.OIDC_REDIRECT_URL || "http://127.0.0.1:5173",
    oidcProviderName: APP_CONFIG.OIDC_PROVIDER_NAME || "OpenID Connect",
    // JWT auth strategy
    jwtEnabled: APP_CONFIG.JWT_ENABLED === "true",
};
