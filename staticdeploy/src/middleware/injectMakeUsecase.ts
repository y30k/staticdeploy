import {
    IArchiver,
    IAuthenticationStrategy,
    IV2AuthorizationStorage,
    ReplaceV2Bindings,
    V2Authorizer,
    IStorages,
    IUsecaseConfig,
} from "@staticdeploy/core";
import { IUsecasesByName } from "@staticdeploy/http-adapters";
import { RequestHandler } from "express";

import IRequestWithAuthToken from "../common/IRequestWithAuthToken";

export default function injectMakeUsecase(
    usecases: IUsecasesByName,
    dependencies: {
        archiver: IArchiver;
        authenticationStrategies: IAuthenticationStrategy[];
        config: IUsecaseConfig;
        storages: IStorages;
        v2Authorization?: IV2AuthorizationStorage;
    }
): RequestHandler {
    const { archiver, authenticationStrategies, config, storages } =
        dependencies;
    return (req: IRequestWithAuthToken, _res, next) => {
        if (dependencies.v2Authorization !== undefined) {
            req.makeV2Authorizer = () =>
                new V2Authorizer(
                    dependencies.v2Authorization!,
                    req.v2Principal
                );
            req.makeReplaceV2Bindings = () =>
                new ReplaceV2Bindings(req.makeV2Authorizer!());
        }
        req.makeUsecase = <Name extends keyof IUsecasesByName>(name: Name) => {
            const UsecaseClass = usecases[name];
            return new UsecaseClass({
                archiver: archiver,
                authenticationStrategies: authenticationStrategies,
                config: config,
                requestContext: {
                    authToken: req.authToken,
                    v2Principal: req.v2Principal,
                },
                storages: storages,
            }) as InstanceType<IUsecasesByName[Name]>;
        };
        next();
    };
}
