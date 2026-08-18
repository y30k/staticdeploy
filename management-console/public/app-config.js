// Safe loopback-only defaults for the Vite development server. Production
// responses replace this script reference with server-generated APP_CONFIG.
window.APP_CONFIG = {
    API_URL: "http://127.0.0.1:3456",
    AUTH_ENFORCED: "false",
    JWT_ENABLED: "false",
    OIDC_CLIENT_ID: "clientId",
    OIDC_CONFIGURATION_URL: "http://127.0.0.1:3456/oidc/configuration",
    OIDC_ENABLED: "false",
    OIDC_PROVIDER_NAME: "Local OpenID Connect",
    OIDC_REDIRECT_URL: "http://127.0.0.1:5173",
};
