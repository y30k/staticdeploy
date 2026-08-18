import { UserType } from "@staticdeploy/core/browser";

export interface IInternalFormValues {
    idp: string;
    idpId: string;
    type: UserType;
    name: string;
    groupsIds: string[];
}

export interface IExternalFormValues {
    idp: string;
    idpId: string;
    type: UserType;
    name: string;
    groupsIds: string[];
}
