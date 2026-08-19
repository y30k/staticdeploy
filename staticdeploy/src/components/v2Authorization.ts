import {
    createV2Authorization,
    V2Authorization,
} from "@staticdeploy/pg-s3-storages";

import IConfig from "../common/IConfig";

/** Fail-closed startup qualification for the M3 control authorization role. */
export default async function getV2Authorization(
    config: IConfig
): Promise<V2Authorization | undefined> {
    if (config.oidcAdministratorGroupIds === undefined) return undefined;
    const authorization = createV2Authorization(config.oidcPostgresUrl!, {
        administratorGroupIds: config.oidcAdministratorGroupIds,
        requiredClaimsVersion: config.oidcAuthorizationClaimsVersion!,
    });
    try {
        await authorization.verifyReady();
        return authorization;
    } catch (error) {
        await authorization.destroy();
        throw error;
    }
}
