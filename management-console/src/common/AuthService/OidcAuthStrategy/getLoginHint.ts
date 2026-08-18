import { User } from "oidc-client-ts";

export default function getLoginHint(user: User): string | undefined {
    const { profile } = user;
    return (
        // Azure AD
        profile.preferred_username ||
        // Google Identity Platform
        profile.sub
    );
}
