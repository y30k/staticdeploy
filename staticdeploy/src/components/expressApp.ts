import {
    IAuthenticationStrategy,
    IStoragesModule,
    IV2AuthorizationStorage,
} from "@staticdeploy/core";
import {
    IUsecasesByName,
    staticServerAdapter,
} from "@staticdeploy/http-adapters";
import tarArchiver from "@staticdeploy/tar-archiver";
import express from "express";
import { Logger } from "pino";
import vhost from "vhost";

import IConfig from "../common/IConfig";
import extractAuthToken from "../middleware/extractAuthToken";
import injectMakeUsecase from "../middleware/injectMakeUsecase";
import getRequestLogger from "./requestLogger";

export default function getExpressApp(options: {
    authenticationStrategies: IAuthenticationStrategy[];
    config: IConfig;
    logger: Logger;
    managementRouter: express.Router;
    storagesModule: IStoragesModule;
    usecases: IUsecasesByName;
    v2Authorization?: IV2AuthorizationStorage;
}): express.Application {
    const {
        authenticationStrategies,
        config,
        logger,
        managementRouter,
        storagesModule,
        usecases,
        v2Authorization,
    } = options;

    return express()
        .disable("x-powered-by")
        .use([
            getRequestLogger(logger),
            extractAuthToken(),
            injectMakeUsecase(usecases, {
                archiver: tarArchiver,
                authenticationStrategies: authenticationStrategies,
                config: { enforceAuth: config.enforceAuth },
                storages: storagesModule.getStorages(),
                v2Authorization,
            }),
            vhost(config.managementHostname, managementRouter),
            staticServerAdapter({ hostnameHeader: config.hostnameHeader }),
        ]);
}
