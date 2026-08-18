import IAuthenticationStrategy from "../dependencies/IAuthenticationStrategy";
import { IIdpUser } from "../entities/User";

export default class Authenticator {
    constructor(
        private authenticationStrategies: IAuthenticationStrategy[],
        private authToken: string | null
    ) {}

    async getIdpUser(): Promise<IIdpUser | null> {
        if (!this.authToken) {
            return null;
        }
        for (const authenticationStrategy of this.authenticationStrategies) {
            const idpUser =
                await authenticationStrategy.getIdpUserFromAuthToken(
                    this.authToken
                );
            if (idpUser !== null) return idpUser;
        }
        return null;
    }
}
