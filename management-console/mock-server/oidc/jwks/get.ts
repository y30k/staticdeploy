import { RequestHandler } from "express";

import { getJwks } from "../state";

export default (async (_req, res) => {
    res.send(await getJwks());
}) as RequestHandler;
