import { IConfiguration } from "@staticdeploy/core/browser";

import { IKVPair } from "../../common/configurationUtils";

export interface IInternalFormValues {
    name: string;
    defaultConfiguration: IKVPair[];
}

export interface IExternalFormValues {
    name: string;
    defaultConfiguration: IConfiguration;
}
