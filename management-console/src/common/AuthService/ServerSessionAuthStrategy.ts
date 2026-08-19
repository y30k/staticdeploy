import IAuthStrategy from "./IAuthStrategy";

interface SessionResponse {
    csrfToken: string;
}

export default class ServerSessionAuthStrategy implements IAuthStrategy {
    name = "oidc";
    readonly usesServerSession = true;
    private csrfToken: string | null = null;

    constructor(
        private readonly authUrl: string,
        public displayName: string
    ) {}

    getCsrfToken = (): string | null => this.csrfToken;

    async init(): Promise<void> {
        this.purgeLegacyOidcStorage();
        const response = await fetch(`${this.authUrl}/session`, {
            credentials: "include",
            headers: { Accept: "application/json" },
            cache: "no-store",
        });
        if (!response.ok) {
            this.csrfToken = null;
            return;
        }
        const body = (await response.json()) as SessionResponse;
        this.csrfToken =
            typeof body.csrfToken === "string" ? body.csrfToken : null;
    }

    async login(): Promise<void> {
        window.location.assign(`${this.authUrl}/login`);
        await new Promise(() => undefined);
    }

    async logout(): Promise<void> {
        const csrfToken = this.csrfToken;
        if (csrfToken === null) return;
        const response = await fetch(`${this.authUrl}/logout`, {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
                "X-StaticDeploy-CSRF": csrfToken,
            },
            body: "{}",
            cache: "no-store",
        });
        if (!response.ok) throw new Error("Server session logout failed");
        this.csrfToken = null;
    }

    private purgeLegacyOidcStorage(): void {
        for (const storage of [window.localStorage, window.sessionStorage]) {
            const keys: string[] = [];
            for (let index = 0; index < storage.length; index++) {
                const key = storage.key(index);
                if (key?.startsWith("oidc.")) keys.push(key);
            }
            for (const key of keys) storage.removeItem(key);
        }
    }

    async getAuthToken(): Promise<string | null> {
        // This marker is used only for AuthService status; it is never sent.
        return this.csrfToken === null ? null : "server-session";
    }
}
