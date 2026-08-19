import { expect } from "chai";
import { Knex } from "knex";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { join } from "node:path";

import {
    V2Authorization,
    V2_CAPABILITIES,
    V2_ROLE_CAPABILITIES,
    V2Actor,
} from "../src/V2Authorization";
import { V2OidcSessions } from "../src/V2Sessions";
import { V2PublicationQueue } from "../src/V2RoutingProjection";
import { createPostgresKnex } from "../src/postgres";
import tables from "../src/common/tables";

const postgresUrl =
    process.env.POSTGRES_TEST_URL ??
    "postgres://postgres:password@127.0.0.1:5432/postgres";

const pause = (milliseconds: number) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds));

const auditActorId = (issuer: string, subject: string): string =>
    `oidc:${createHash("sha256")
        .update(
            `${issuer.length}:${issuer}${subject.length}:${subject}`,
            "utf8"
        )
        .digest("hex")}`;

const expectUtcDate = (value: unknown): void => {
    expect(value).to.be.instanceOf(Date);
    expect((value as Date).toISOString()).to.match(/Z$/);
};

const expectRejected = async (
    operation: Promise<unknown>,
    message?: string
): Promise<void> => {
    let failure: unknown;
    try {
        await operation;
    } catch (error) {
        failure = error;
    }
    expect(failure).to.be.instanceOf(Error);
    if (message !== undefined)
        expect((failure as Error).message).to.include(message);
};

describe("M3-07 role bindings and authorization policy", () => {
    let admin: Knex;
    let rootDatabase: Knex;
    let database: Knex.Transaction;
    let databaseName: string;
    let authorization: V2Authorization;
    const appA = "81000000-0000-4000-8000-000000000001";
    const appB = "81000000-0000-4000-8000-000000000002";
    const administratorGroup = "stable-admin-id";

    before(async () => {
        admin = createPostgresKnex(postgresUrl);
        databaseName = `v2_authz_${process.pid}_${Date.now()}`;
        await admin.raw(`CREATE DATABASE ??`, [databaseName]);
        const parsed = new URL(postgresUrl);
        parsed.pathname = `/${databaseName}`;
        rootDatabase = createPostgresKnex(parsed.toString());
        await rootDatabase.migrate.latest({
            directory: join(__dirname, "../lib/migrations"),
            loadExtensions: [".js"],
        });
        const policy = {
            administratorGroupIds: [administratorGroup],
            requiredClaimsVersion: 1,
        };
        await rootDatabase("v2_authorization_policy").insert({
            singleton: true,
            administrator_groups: policy.administratorGroupIds,
            required_claims_version: policy.requiredClaimsVersion,
            configuration_digest: createHash("sha256")
                .update(JSON.stringify(policy), "utf8")
                .digest("hex"),
        });
    });

    after(async () => {
        await rootDatabase?.destroy();
        if (admin !== undefined) {
            await admin.raw(`DROP DATABASE IF EXISTS ?? WITH (FORCE)`, [
                databaseName,
            ]);
            await admin.destroy();
        }
    });

    const insertApp = async (id: string, name: string) => {
        await database(tables.v2Applications).insert({
            id,
            name,
            routing_id: randomUUID(),
        });
    };

    const actor = async (
        name: string,
        groups: string[],
        claimsVersion = 1
    ): Promise<V2Actor> => {
        const sessionId = randomUUID();
        const sortedGroups = [...groups].sort((left, right) =>
            Buffer.compare(
                Buffer.from(left, "utf8"),
                Buffer.from(right, "utf8")
            )
        );
        await database.raw(
            `INSERT INTO public.${tables.v2Sessions} (
                id, subject_id, issuer, claims, claims_version,
                csrf_token_digest, created_at, last_seen_at,
                idle_expires_at, absolute_expires_at
            ) VALUES (?, ?, 'https://idp.example', ?::jsonb, ?, ?,
                clock_timestamp(), clock_timestamp(),
                clock_timestamp() + interval '1 hour',
                clock_timestamp() + interval '8 hours')`,
            [
                sessionId,
                name,
                JSON.stringify({ sub: name, groups: sortedGroups }),
                claimsVersion,
                "a".repeat(64),
            ]
        );
        return {
            sessionId,
            subjectId: name,
            issuer: "https://idp.example",
            groups: sortedGroups,
            claimsVersion,
        };
    };

    const waitForBlocked = async (
        functionName: string,
        expectedCount = 1
    ): Promise<void> => {
        const deadline = Date.now() + 5_000;
        while (Date.now() < deadline) {
            const result = await rootDatabase.raw(
                `SELECT count(*)::integer AS count FROM pg_stat_activity
                  WHERE datname = current_database()
                    AND pid <> pg_backend_pid()
                    AND wait_event_type = 'Lock'
                    AND query LIKE ?`,
                [`%${functionName}%`]
            );
            if (Number(result.rows[0].count) >= expectedCount) return;
            await pause(20);
        }
        throw new Error(`timed out waiting for blocked ${functionName}`);
    };

    const bind = async (
        applicationId: string,
        groupId: string,
        role: "OWNER" | "PUBLISHER" | "VIEWER"
    ) => {
        await database(tables.v2Bindings).insert({
            id: randomUUID(),
            application_id: applicationId,
            group_id: groupId,
            role,
            created_by: "fixture",
        });
    };

    beforeEach(async () => {
        database = await rootDatabase.transaction();
        authorization = new V2Authorization(database, {
            administratorGroupIds: [administratorGroup],
            requiredClaimsVersion: 1,
        });
        await insertApp(appA, `app-a-${randomBytes(4).toString("hex")}`);
        await insertApp(appB, `app-b-${randomBytes(4).toString("hex")}`);
        await bind(appA, "owner-a", "OWNER");
        await bind(appA, "publisher-a", "PUBLISHER");
        await bind(appA, "viewer-a", "VIEWER");
    });

    afterEach(async () => {
        if (!database.isCompleted()) await database.rollback();
    });

    it("AUTHZ-01 provisions one immutable canonical policy and compares actual values", async () => {
        const policy = {
            administratorGroupIds: [administratorGroup],
            requiredClaimsVersion: 1,
        };
        const digest = createHash("sha256")
            .update(JSON.stringify(policy), "utf8")
            .digest("hex");
        await database.raw(
            "select public.v2_initialize_authorization_policy(?, ?, ?)",
            [[administratorGroup], 1, digest]
        );
        for (const groups of [
            [administratorGroup, administratorGroup],
            [" bad"],
            [""],
        ])
            await expectRejected(
                database.transaction((savepoint) =>
                    savepoint.raw(
                        "select public.v2_initialize_authorization_policy(?, ?, ?)",
                        [groups, 1, digest]
                    )
                )
            );
        await expectRejected(
            database.transaction((savepoint) =>
                savepoint.raw(
                    "select public.v2_initialize_authorization_policy(?, ?, ?)",
                    [["different-admin"], 1, digest]
                )
            ),
            "conflicts with immutable configuration"
        );
        expect(
            () =>
                new V2Authorization(database, {
                    administratorGroupIds: [administratorGroup],
                    requiredClaimsVersion: 2,
                })
        ).to.throw("invalid authorization policy configuration");
    });

    it("AUTHZ-01 generates the complete role by operation matrix", async () => {
        const actors: Record<string, V2Actor> = {
            ADMINISTRATOR: await actor("admin", [administratorGroup]),
            OWNER: await actor("owner", ["owner-a"]),
            PUBLISHER: await actor("publisher", ["publisher-a"]),
            VIEWER: await actor("viewer", ["viewer-a"]),
            DENIED: await actor("denied", ["unknown"]),
        };
        for (const [role, candidate] of Object.entries(actors))
            for (const capability of V2_CAPABILITIES) {
                const decision =
                    capability === "APPLICATION_CREATE"
                        ? await authorization.authorizeApplicationCreate(
                              candidate
                          )
                        : await authorization.authorize(
                              candidate,
                              appA,
                              capability
                          );
                expect(decision.allowed, `${role} ${capability}`).to.equal(
                    V2_ROLE_CAPABILITIES[
                        role as keyof typeof V2_ROLE_CAPABILITIES
                    ].includes(capability)
                );
                expect(decision.effectiveRole).to.equal(
                    capability === "APPLICATION_CREATE" &&
                        role !== "ADMINISTRATOR"
                        ? "DENIED"
                        : role
                );
            }
        expect(await database(tables.v2AuditEvents).count("*")).to.deep.equal([
            { count: "75" },
        ]);
    });

    it("AUTHZ-01 scopes exact stable groups and grants unknown values nothing", async () => {
        for (const group of [
            "owner-a",
            "OWNER-A",
            "оwner-a",
            "renamed-owner-a",
            "unknown",
        ]) {
            const candidate = await actor(`candidate-${randomUUID()}`, [group]);
            expect(
                (
                    await authorization.authorize(
                        candidate,
                        appB,
                        "APPLICATION_READ"
                    )
                ).allowed
            ).to.equal(false);
        }
        const malformed = await actor("malformed-group", [" owner-a"]);
        await expectRejected(
            authorization.authorize(malformed, appB, "APPLICATION_READ"),
            "invalid stable group identifiers"
        );
        const owner = await actor("scoped-owner", ["owner-a"]);
        expect(
            (await authorization.authorize(owner, appA, "APPLICATION_UPDATE"))
                .allowed
        ).to.equal(true);
        expect(
            (await authorization.authorize(owner, appB, "APPLICATION_UPDATE"))
                .allowed
        ).to.equal(false);
        expect(
            () =>
                new V2Authorization(database, {
                    administratorGroupIds: ["", administratorGroup],
                    requiredClaimsVersion: 1,
                })
        ).to.throw("invalid stable group identifiers");
    });

    it("AUTHZ-01 replaces the whole set with delegation, fencing, and idempotency", async () => {
        const owner = await actor("binding-owner", ["owner-a"]);
        const desired = [
            { groupId: "owner-a", role: "OWNER" as const },
            { groupId: "new-owner", role: "OWNER" as const },
            { groupId: "new-publisher", role: "PUBLISHER" as const },
            { groupId: "new-viewer", role: "VIEWER" as const },
        ];
        const applied = await authorization.replaceBindings({
            actor: owner,
            applicationId: appA,
            expectedVersion: 1,
            idempotencyKey: "replace-1",
            bindings: desired,
        });
        expect(applied.outcome).to.equal("APPLIED");
        expect(applied.resultingVersion).to.equal(2);
        expect(
            await database(tables.v2Bindings)
                .where({ application_id: appA })
                .select("group_id", "role")
                .orderBy("group_id")
        ).to.deep.equal([
            { group_id: "new-owner", role: "OWNER" },
            { group_id: "new-publisher", role: "PUBLISHER" },
            { group_id: "new-viewer", role: "VIEWER" },
            { group_id: "owner-a", role: "OWNER" },
        ]);
        const replay = await authorization.replaceBindings({
            actor: owner,
            applicationId: appA,
            expectedVersion: 1,
            idempotencyKey: "replace-1",
            bindings: [...desired].reverse(),
        });
        expect(replay).to.include({
            outcome: "APPLIED",
            resultingVersion: 2,
            effectiveRole: "OWNER",
        });
        expect(
            await database(tables.v2AuditEvents)
                .where({ action: "BINDINGS_REPLACE" })
                .count("*")
        ).to.deep.equal([{ count: "1" }]);
        const successAudit = await database(tables.v2AuditEvents)
            .where({ action: "BINDINGS_REPLACE" })
            .first();
        expect(successAudit.actor_id).to.equal(
            auditActorId("https://idp.example", "binding-owner")
        );
        expect(successAudit.application_id).to.equal(appA);
        expect(successAudit.release_id).to.equal(null);
        expect(successAudit.metadata).to.deep.include({
            objectKind: "BINDINGS",
            operation: "BINDINGS_REPLACE",
            result: "APPLIED",
            role: "OWNER",
            source: "APPLICATION_BINDING",
            bindingVersion: 2,
            bindingCount: 4,
        });
        expect(successAudit.metadata.requestDigest).to.match(/^[0-9a-f]{64}$/);
        expectUtcDate(successAudit.occurred_at);
        await expectRejected(
            database.transaction((savepoint) =>
                new V2Authorization(savepoint, {
                    administratorGroupIds: [administratorGroup],
                    requiredClaimsVersion: 1,
                }).replaceBindings({
                    actor: owner,
                    applicationId: appA,
                    expectedVersion: 1,
                    idempotencyKey: "replace-1",
                    bindings: [
                        { groupId: "owner-a", role: "OWNER" },
                        { groupId: "conflict", role: "VIEWER" },
                    ],
                })
            ),
            "idempotency key conflicts"
        );
        const noOp = await authorization.replaceBindings({
            actor: owner,
            applicationId: appA,
            expectedVersion: 2,
            idempotencyKey: "unchanged-complete-set",
            bindings: desired,
        });
        expect(noOp).to.include({ outcome: "APPLIED", resultingVersion: 2 });
        const promoted = desired.map((binding) =>
            binding.groupId === "new-viewer"
                ? { ...binding, role: "PUBLISHER" as const }
                : binding
        );
        expect(
            await authorization.replaceBindings({
                actor: owner,
                applicationId: appA,
                expectedVersion: 2,
                idempotencyKey: "owner-promotion",
                bindings: promoted,
            })
        ).to.include({ outcome: "APPLIED", resultingVersion: 3 });
        const delegatedOwner = await actor("delegated-owner", ["new-owner"]);
        const demoted = promoted.map((binding) =>
            binding.groupId === "owner-a"
                ? { ...binding, role: "VIEWER" as const }
                : binding
        );
        expect(
            await authorization.replaceBindings({
                actor: delegatedOwner,
                applicationId: appA,
                expectedVersion: 3,
                idempotencyKey: "owner-self-demotion",
                bindings: demoted,
            })
        ).to.include({ outcome: "APPLIED", resultingVersion: 4 });
        const handoff = await authorization.replaceBindings({
            actor: delegatedOwner,
            applicationId: appA,
            expectedVersion: 4,
            idempotencyKey: "owner-handoff",
            bindings: [{ groupId: "successor-owner", role: "OWNER" }],
        });
        expect(handoff.outcome).to.equal("APPLIED");
        expect(
            await database(tables.v2Bindings)
                .where({ application_id: appA })
                .select("group_id", "role")
        ).to.deep.equal([{ group_id: "successor-owner", role: "OWNER" }]);
    });

    it("AUTHZ-01 hashes bytewise-equivalent Unicode sets deterministically", async () => {
        const administrator = await actor("unicode-admin", [
            administratorGroup,
        ]);
        const bindings = [
            { groupId: "é", role: "OWNER" as const },
            { groupId: "é", role: "VIEWER" as const },
            { groupId: "Ω", role: "PUBLISHER" as const },
        ];
        const first = await authorization.replaceBindings({
            actor: administrator,
            applicationId: appB,
            expectedVersion: 1,
            idempotencyKey: "unicode-byte-order",
            bindings,
        });
        const replay = await authorization.replaceBindings({
            actor: administrator,
            applicationId: appB,
            expectedVersion: 1,
            idempotencyKey: "unicode-byte-order",
            bindings: [...bindings].reverse(),
        });
        expect(replay.resultDigest).to.equal(first.resultDigest);
        expect(
            await database(tables.v2Bindings)
                .where({ application_id: appB })
                .count("*")
        ).to.deep.equal([{ count: "3" }]);
    });

    it("AUTHZ-01 makes existing and missing target denial results indistinguishable", async () => {
        await database(tables.v2Applications)
            .where({ id: appA })
            .update({ binding_version: 9 });
        const denied = await actor("target-denied", ["unknown"]);
        const existing = await authorization.authorize(
            denied,
            appA,
            "APPLICATION_READ"
        );
        const missing = await authorization.authorize(
            denied,
            randomUUID(),
            "APPLICATION_READ"
        );
        expect(existing).to.deep.equal(missing);
        const replaceExisting = await authorization.replaceBindings({
            actor: denied,
            applicationId: appA,
            expectedVersion: 9,
            idempotencyKey: "existing-denied",
            bindings: [],
        });
        const replaceMissing = await authorization.replaceBindings({
            actor: denied,
            applicationId: randomUUID(),
            expectedVersion: 1,
            idempotencyKey: "missing-denied",
            bindings: [],
        });
        expect(replaceExisting).to.deep.equal(replaceMissing);
        expect(replaceExisting.resultingVersion).to.equal(null);
        expect(replaceExisting.resultDigest).to.equal(null);
    });

    it("AUTHZ-01 authorizes before idempotency and records only a safe denial", async () => {
        const denied = await actor("denied-replace", ["viewer-a"]);
        const before = await database(tables.v2Bindings)
            .where({ application_id: appA })
            .select("group_id", "role")
            .orderBy("group_id");
        const result = await authorization.replaceBindings({
            actor: denied,
            applicationId: appA,
            expectedVersion: 1,
            idempotencyKey: "known-admin-key",
            bindings: [{ groupId: "attacker", role: "OWNER" }],
        });
        expect(result.outcome).to.equal("DENIED");
        expect(await database("v2_binding_requests").count("*")).to.deep.equal([
            { count: "0" },
        ]);
        expect(
            await database(tables.v2Bindings)
                .where({ application_id: appA })
                .select("group_id", "role")
                .orderBy("group_id")
        ).to.deep.equal(before);
        const audit = await database(tables.v2AuditEvents).first();
        expect(audit.actor_id).to.equal(
            auditActorId("https://idp.example", "denied-replace")
        );
        expect(audit.action).to.equal("BINDINGS_REPLACE");
        expect(audit.application_id).to.equal(appA);
        expect(audit.release_id).to.equal(null);
        expect(audit.metadata).to.deep.equal({
            objectKind: "BINDINGS",
            operation: "BINDINGS_REPLACE",
            result: "DENIED",
            role: "VIEWER",
            source: "APPLICATION_BINDING",
            reason: "NOT_AUTHORIZED",
        });
        expectUtcDate(audit.occurred_at);
        expect(JSON.stringify(audit)).not.to.include("known-admin-key");
        expect(JSON.stringify(audit)).not.to.include("attacker");
    });

    it("AUTHZ-01 linearizes same and different key races on independent connections", async () => {
        const applicationId = randomUUID();
        const sessionId = randomUUID();
        await rootDatabase(tables.v2Applications).insert({
            id: applicationId,
            name: `race-${randomBytes(6).toString("hex")}`,
            routing_id: randomUUID(),
        });
        await rootDatabase.raw(
            `INSERT INTO public.${tables.v2Sessions} (
                id, subject_id, issuer, claims, claims_version,
                csrf_token_digest, created_at, last_seen_at,
                idle_expires_at, absolute_expires_at
            ) VALUES (?, 'race-admin', 'https://idp.example', ?::jsonb, 1, ?,
                clock_timestamp(), clock_timestamp(),
                clock_timestamp() + interval '1 hour',
                clock_timestamp() + interval '8 hours')`,
            [
                sessionId,
                JSON.stringify({
                    sub: "race-admin",
                    groups: [administratorGroup],
                }),
                "a".repeat(64),
            ]
        );
        const service = new V2Authorization(rootDatabase, {
            administratorGroupIds: [administratorGroup],
            requiredClaimsVersion: 1,
        });
        const adminActor: V2Actor = {
            sessionId,
            subjectId: "race-admin",
            issuer: "https://idp.example",
            groups: [administratorGroup],
            claimsVersion: 1,
        };
        const same = {
            actor: adminActor,
            applicationId,
            expectedVersion: 1,
            idempotencyKey: "same-race",
            bindings: [{ groupId: "same", role: "OWNER" as const }],
        };
        const sameBlocker = await rootDatabase.transaction();
        await sameBlocker.raw(
            `SELECT 1 FROM public.${tables.v2Applications}
              WHERE id = ? FOR UPDATE`,
            [applicationId]
        );
        const sameRacePromise = Promise.all([
            service.replaceBindings(same),
            service.replaceBindings(same),
        ]);
        await waitForBlocked("v2_replace_bindings", 2);
        await sameBlocker.commit();
        const sameRace = await sameRacePromise;
        expect(sameRace.map(({ outcome }) => outcome)).to.deep.equal([
            "APPLIED",
            "APPLIED",
        ]);
        expect(
            await rootDatabase(tables.v2AuditEvents)
                .where({
                    application_id: applicationId,
                    action: "BINDINGS_REPLACE",
                })
                .count("*")
        ).to.deep.equal([{ count: "1" }]);
        const version = sameRace[0].resultingVersion!;
        const differentBlocker = await rootDatabase.transaction();
        await differentBlocker.raw(
            `SELECT 1 FROM public.${tables.v2Applications}
              WHERE id = ? FOR UPDATE`,
            [applicationId]
        );
        const differentPromise = Promise.all([
            service.replaceBindings({
                ...same,
                expectedVersion: version,
                idempotencyKey: "different-a",
                bindings: [{ groupId: "set-a", role: "OWNER" }],
            }),
            service.replaceBindings({
                ...same,
                expectedVersion: version,
                idempotencyKey: "different-b",
                bindings: [{ groupId: "set-b", role: "OWNER" }],
            }),
        ]);
        await waitForBlocked("v2_replace_bindings", 2);
        await differentBlocker.commit();
        const different = await differentPromise;
        expect(
            different.filter(({ outcome }) => outcome === "APPLIED")
        ).to.have.length(1);
        expect(
            different.filter(({ outcome }) => outcome === "VERSION_CONFLICT")
        ).to.have.length(1);
        const retained = await rootDatabase(tables.v2Bindings)
            .where({ application_id: applicationId })
            .select("group_id");
        expect(retained).to.have.length(1);
        expect(["set-a", "set-b"]).to.include(retained[0].group_id);

        const parallelA = randomUUID();
        const parallelB = randomUUID();
        await rootDatabase(tables.v2Applications).insert([
            {
                id: parallelA,
                name: `parallel-a-${randomBytes(4).toString("hex")}`,
                routing_id: randomUUID(),
            },
            {
                id: parallelB,
                name: `parallel-b-${randomBytes(4).toString("hex")}`,
                routing_id: randomUUID(),
            },
        ]);
        const crossBlocker = await rootDatabase.transaction();
        await crossBlocker.raw(
            `SELECT 1 FROM public.${tables.v2Applications}
              WHERE id = ? FOR UPDATE`,
            [parallelA]
        );
        const blockedCrossApp = service.replaceBindings({
            ...same,
            applicationId: parallelA,
            idempotencyKey: "parallel-a",
        });
        await waitForBlocked("v2_replace_bindings");
        const independent = await Promise.race([
            service.replaceBindings({
                ...same,
                applicationId: parallelB,
                idempotencyKey: "parallel-b",
            }),
            pause(2_000).then(() => {
                throw new Error("cross-application replacement serialized");
            }),
        ]);
        expect(independent.outcome).to.equal("APPLIED");
        await crossBlocker.commit();
        expect((await blockedCrossApp).outcome).to.equal("APPLIED");
    });

    it("AUTHZ-01 rolls every replacement statement back on injected failures", async () => {
        const adminActor = await actor("rollback-admin", [administratorGroup]);
        const before = await database(tables.v2Bindings)
            .where({ application_id: appA })
            .select("group_id", "role")
            .orderBy("group_id");
        const phases = [
            { event: "DELETE", table: tables.v2Bindings },
            { event: "INSERT", table: tables.v2Bindings },
            { event: "UPDATE", table: tables.v2Applications },
            { event: "INSERT", table: "v2_binding_requests" },
            { event: "INSERT", table: tables.v2AuditEvents },
        ];
        for (const [index, phase] of phases.entries()) {
            const trigger = `v2_test_failure_${index}`;
            await database.raw(`
                CREATE FUNCTION public.${trigger}() RETURNS trigger
                LANGUAGE plpgsql AS $$ BEGIN
                    RAISE EXCEPTION 'injected ${trigger}';
                END $$;
                CREATE TRIGGER ${trigger} BEFORE ${phase.event}
                ON public.${phase.table} FOR EACH ROW
                EXECUTE FUNCTION public.${trigger}()
            `);
            try {
                await expectRejected(
                    database.transaction(async (savepoint) => {
                        const isolated = new V2Authorization(savepoint, {
                            administratorGroupIds: [administratorGroup],
                            requiredClaimsVersion: 1,
                        });
                        await isolated.replaceBindings({
                            actor: adminActor,
                            applicationId: appA,
                            expectedVersion: 1,
                            idempotencyKey: `rollback-${index}`,
                            bindings: [
                                {
                                    groupId: `replacement-${index}`,
                                    role: "OWNER",
                                },
                            ],
                        });
                    }),
                    `injected ${trigger}`
                );
            } finally {
                await database.raw(`
                    DROP TRIGGER ${trigger} ON public.${phase.table};
                    DROP FUNCTION public.${trigger}()
                `);
            }
            expect(
                await database(tables.v2Bindings)
                    .where({ application_id: appA })
                    .select("group_id", "role")
                    .orderBy("group_id")
            ).to.deep.equal(before);
            expect(
                await database("v2_binding_requests")
                    .where({ application_id: appA })
                    .count("*")
            ).to.deep.equal([{ count: "0" }]);
            expect(
                await database(tables.v2AuditEvents)
                    .where({ application_id: appA })
                    .count("*")
            ).to.deep.equal([{ count: "0" }]);
        }
    });

    it("AUTHZ-01 fences claims changes and observes binding changes immediately", async () => {
        const oldActor = await actor("changing-user", ["owner-a"]);
        expect(
            (
                await authorization.authorize(
                    oldActor,
                    appA,
                    "APPLICATION_UPDATE"
                )
            ).allowed
        ).to.equal(true);
        await database(tables.v2Sessions)
            .where({ id: oldActor.sessionId })
            .update({
                claims: JSON.stringify({
                    sub: "changing-user",
                    groups: ["unknown"],
                }),
                claims_version: 2,
            });
        await database
            .transaction(async (savepoint) => {
                const isolated = new V2Authorization(savepoint, {
                    administratorGroupIds: [administratorGroup],
                    requiredClaimsVersion: 1,
                });
                await expectRejected(
                    isolated.authorize(oldActor, appA, "APPLICATION_UPDATE"),
                    "session authorization principal is stale"
                );
                throw new Error("rollback stale savepoint");
            })
            .catch((error) => {
                expect((error as Error).message).to.equal(
                    "rollback stale savepoint"
                );
            });

        const current = await actor("current-user", ["publisher-a"]);
        expect(
            (await authorization.authorize(current, appA, "PUBLISH")).allowed
        ).to.equal(true);
        await database(tables.v2Bindings)
            .where({ application_id: appA, group_id: "publisher-a" })
            .update({ role: "VIEWER" });
        expect(
            (await authorization.authorize(current, appA, "PUBLISH")).allowed
        ).to.equal(false);
    });

    it("AUTHZ-01 fences claims and binding changes across real lock waits", async () => {
        const applicationId = randomUUID();
        const sessionId = randomUUID();
        await rootDatabase(tables.v2Applications).insert({
            id: applicationId,
            name: `fence-${randomBytes(6).toString("hex")}`,
            routing_id: randomUUID(),
        });
        await rootDatabase(tables.v2Bindings).insert({
            id: randomUUID(),
            application_id: applicationId,
            group_id: "race-publisher",
            role: "PUBLISHER",
            created_by: "fixture",
        });
        await rootDatabase.raw(
            `INSERT INTO public.${tables.v2Sessions} (
                id, subject_id, issuer, claims, claims_version,
                csrf_token_digest, created_at, last_seen_at,
                idle_expires_at, absolute_expires_at
            ) VALUES (?, 'race-user', 'https://idp.example', ?::jsonb, 1, ?,
                clock_timestamp(), clock_timestamp(),
                clock_timestamp() + interval '1 hour',
                clock_timestamp() + interval '8 hours')`,
            [
                sessionId,
                JSON.stringify({
                    sub: "race-user",
                    groups: ["race-publisher"],
                }),
                "b".repeat(64),
            ]
        );
        const service = new V2Authorization(rootDatabase, {
            administratorGroupIds: [administratorGroup],
            requiredClaimsVersion: 1,
        });
        const oldActor: V2Actor = {
            sessionId,
            subjectId: "race-user",
            issuer: "https://idp.example",
            groups: ["race-publisher"],
            claimsVersion: 1,
        };
        const sessionBlocker = await rootDatabase.transaction();
        await sessionBlocker.raw(
            `SELECT 1 FROM public.${tables.v2Sessions} WHERE id = ? FOR UPDATE`,
            [sessionId]
        );
        const staleDecision = service.authorize(
            oldActor,
            applicationId,
            "PUBLISH"
        );
        await waitForBlocked("v2_authorize_operation");
        await sessionBlocker(tables.v2Sessions)
            .where({ id: sessionId })
            .update({
                claims: JSON.stringify({
                    sub: "race-user",
                    groups: ["unknown"],
                }),
                claims_version: 2,
            });
        await sessionBlocker.commit();
        await expectRejected(staleDecision, "principal is stale");

        await rootDatabase(tables.v2Sessions)
            .where({ id: sessionId })
            .update({
                claims: JSON.stringify({
                    sub: "race-user",
                    groups: ["race-publisher"],
                }),
                claims_version: 3,
            });
        const currentActor = { ...oldActor, claimsVersion: 3 };
        const appBlocker = await rootDatabase.transaction();
        await appBlocker.raw(
            `SELECT 1 FROM public.${tables.v2Applications} WHERE id = ? FOR UPDATE`,
            [applicationId]
        );
        const changedDecision = service.authorize(
            currentActor,
            applicationId,
            "PUBLISH"
        );
        await waitForBlocked("v2_authorize_operation");
        await appBlocker(tables.v2Bindings)
            .where({
                application_id: applicationId,
                group_id: "race-publisher",
            })
            .update({ role: "VIEWER" });
        await appBlocker.commit();
        expect((await changedDecision).allowed).to.equal(false);
    });

    it("TM-AUD-01 is append-only, bounded, complete, and canary-safe", async () => {
        const viewer = await actor("audit-viewer", ["viewer-a"]);
        await authorization.authorize(viewer, appA, "AUDIT_READ");
        await authorization.authorize(viewer, appA, "APPLICATION_UPDATE");
        const decisions = await database(tables.v2AuditEvents)
            .where({
                action: "AUTHORIZATION_DECISION",
                actor_id: auditActorId("https://idp.example", "audit-viewer"),
            })
            .orderBy("occurred_at", "asc");
        expect(decisions).to.have.length(2);
        for (const [index, expected] of [
            { operation: "AUDIT_READ", result: "ALLOWED" },
            { operation: "APPLICATION_UPDATE", result: "DENIED" },
        ].entries()) {
            const decision = decisions[index];
            expect(decision.actor_id).to.equal(
                auditActorId("https://idp.example", "audit-viewer")
            );
            expect(decision.application_id).to.equal(appA);
            expect(decision.release_id).to.equal(null);
            expect(decision.metadata).to.deep.equal({
                objectKind: "APPLICATION",
                operation: expected.operation,
                result: expected.result,
                role: "VIEWER",
                source: "APPLICATION_BINDING",
                ...(expected.result === "ALLOWED" ? { bindingVersion: 1 } : {}),
            });
            expectUtcDate(decision.occurred_at);
        }

        const lifecycleSessionId = randomUUID();
        await database.raw(
            "select public.v2_create_or_replace_session(?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?)",
            [
                null,
                lifecycleSessionId,
                "audit-lifecycle-user",
                "https://idp.example",
                JSON.stringify({ sub: "audit-lifecycle-user", groups: [] }),
                "b".repeat(64),
                "primary",
                Buffer.alloc(12, 1),
                Buffer.alloc(16, 2),
                60_000,
                120_000,
            ]
        );
        await database.raw("select public.v2_revoke_session(?, ?)", [
            lifecycleSessionId,
            "USER_LOGOUT",
        ]);
        const lifecycleAudits = await database(tables.v2AuditEvents)
            .where({
                actor_id: auditActorId(
                    "https://idp.example",
                    "audit-lifecycle-user"
                ),
            })
            .orderBy("occurred_at", "asc");
        expect(lifecycleAudits).to.have.length(2);
        expect(lifecycleAudits[0]).to.include({
            action: "AUTH_LOGIN",
            application_id: null,
            release_id: null,
        });
        expect(lifecycleAudits[0].metadata).to.deep.equal({
            issuer: "https://idp.example",
            objectKind: "SESSION",
            result: "SUCCESS",
        });
        expectUtcDate(lifecycleAudits[0].occurred_at);
        expect(lifecycleAudits[1]).to.include({
            action: "AUTH_LOGOUT",
            application_id: null,
            release_id: null,
        });
        expect(lifecycleAudits[1].metadata).to.deep.equal({
            objectKind: "SESSION",
            reason: "USER_LOGOUT",
            result: "SUCCESS",
        });
        expectUtcDate(lifecycleAudits[1].occurred_at);

        const event = await database(tables.v2AuditEvents).first("id");
        for (const operation of [
            (savepoint: Knex.Transaction) =>
                savepoint(tables.v2AuditEvents)
                    .where({ id: event.id })
                    .update({ action: "TAMPERED" }),
            (savepoint: Knex.Transaction) =>
                savepoint(tables.v2AuditEvents).where({ id: event.id }).del(),
            (savepoint: Knex.Transaction) =>
                savepoint.raw(`TRUNCATE public.${tables.v2AuditEvents}`),
            (savepoint: Knex.Transaction) =>
                savepoint(tables.v2AuditEvents).insert({
                    id: randomUUID(),
                    actor_id: "actor",
                    action: "UNSAFE",
                    metadata: {
                        token: "access-canary",
                        value: "x".repeat(5000),
                    },
                }),
        ])
            await expectRejected(
                database.transaction(async (savepoint) => operation(savepoint))
            );
        await database(tables.v2AuditEvents).insert({
            id: randomUUID(),
            actor_id: "oidc:" + "a".repeat(64),
            action: "AUTH_LOGIN",
            metadata: {
                issuer: "x".repeat(2048),
                objectKind: "SESSION",
                result: "SUCCESS",
            },
        });
        await expectRejected(
            database.transaction((savepoint) =>
                savepoint(tables.v2AuditEvents).insert({
                    id: randomUUID(),
                    actor_id: "oidc:" + "a".repeat(64),
                    action: "AUTH_LOGIN",
                    metadata: {
                        issuer: "x".repeat(2049),
                        objectKind: "SESSION",
                        result: "SUCCESS",
                    },
                })
            )
        );
        const safeMetadata = {
            issuer: "https://idp.example",
            objectId: appA,
            operation: "APPLICATION_READ",
            result: "DENIED",
            reason: "NOT_AUTHORIZED",
            role: "DENIED",
            source: "NONE",
            objectKind: "APPLICATION",
            bindingVersion: 1,
            requestDigest: "d".repeat(64),
            bindingCount: 0,
            eventVersion: 1,
        };
        expect(Object.keys(safeMetadata)).to.have.length(12);
        await database(tables.v2AuditEvents).insert({
            id: randomUUID(),
            actor_id: "oidc:" + "a".repeat(64),
            action: "AUTHORIZATION_DECISION",
            metadata: safeMetadata,
        });
        await expectRejected(
            database.transaction((savepoint) =>
                savepoint(tables.v2AuditEvents).insert({
                    id: randomUUID(),
                    actor_id: "oidc:" + "a".repeat(64),
                    action: "AUTHORIZATION_DECISION",
                    metadata: { ...safeMetadata, claimsVersion: 1 },
                })
            )
        );

        const baseBytes = Number(
            (
                await database.raw(
                    `SELECT octet_length(jsonb_build_object(
                        'issuer', repeat('i', 2048), 'objectId', ''
                    )::text) AS bytes`
                )
            ).rows[0].bytes
        );
        const exactObjectLength = 4096 - baseBytes;
        expect(exactObjectLength).to.be.within(1, 2048);
        const exactBytesMetadata = {
            issuer: "i".repeat(2048),
            objectId: "o".repeat(exactObjectLength),
        };
        expect(
            Number(
                (
                    await database.raw(
                        "SELECT octet_length(?::jsonb::text) AS bytes",
                        [JSON.stringify(exactBytesMetadata)]
                    )
                ).rows[0].bytes
            )
        ).to.equal(4096);
        await database(tables.v2AuditEvents).insert({
            id: randomUUID(),
            actor_id: "oidc:" + "a".repeat(64),
            action: "AUTH_LOGIN",
            metadata: exactBytesMetadata,
        });
        await expectRejected(
            database.transaction((savepoint) =>
                savepoint(tables.v2AuditEvents).insert({
                    id: randomUUID(),
                    actor_id: "oidc:" + "a".repeat(64),
                    action: "AUTH_LOGIN",
                    metadata: {
                        ...exactBytesMetadata,
                        objectId: "o".repeat(exactObjectLength + 1),
                    },
                })
            )
        );

        for (const invalidMetadata of [
            { ...safeMetadata, requestDigest: "D".repeat(64) },
            { ...safeMetadata, requestDigest: "d".repeat(63) },
            { ...safeMetadata, bindingVersion: -1 },
            { ...safeMetadata, bindingCount: 1.5 },
            { ...safeMetadata, eventVersion: "1" },
            { ...safeMetadata, issuer: ["nested"] },
            { ...safeMetadata, objectId: { nested: true } },
            { ...safeMetadata, policyVersion: null },
        ])
            await expectRejected(
                database.transaction((savepoint) =>
                    savepoint(tables.v2AuditEvents).insert({
                        id: randomUUID(),
                        actor_id: "oidc:" + "a".repeat(64),
                        action: "AUTHORIZATION_DECISION",
                        metadata: invalidMetadata,
                    })
                )
            );
        for (const metadata of [
            { bindingVersion: 1 },
            { eventVersion: 1 },
            { claimsVersion: 1 },
            { policyVersion: 1 },
            { bindingCount: 0 },
            { bindingCount: 256 },
        ])
            await database(tables.v2AuditEvents).insert({
                id: randomUUID(),
                actor_id: "oidc:" + "a".repeat(64),
                action: "AUTHORIZATION_DECISION",
                metadata,
            });
        for (const metadata of [
            { bindingVersion: 0 },
            { eventVersion: 0 },
            { claimsVersion: 0 },
            { policyVersion: 0 },
            { bindingCount: 257 },
        ])
            await expectRejected(
                database.transaction((savepoint) =>
                    savepoint(tables.v2AuditEvents).insert({
                        id: randomUUID(),
                        actor_id: "oidc:" + "a".repeat(64),
                        action: "AUTHORIZATION_DECISION",
                        metadata,
                    })
                )
            );
        await database.raw(
            `INSERT INTO public.${tables.v2AuditEvents}
            (id, actor_id, action, metadata) VALUES
            (?, ?, 'AUTHORIZATION_DECISION',
             jsonb_build_object('bindingVersion', 9223372036854775807))`,
            [randomUUID(), "oidc:" + "a".repeat(64)]
        );
        await expectRejected(
            database.transaction((savepoint) =>
                savepoint.raw(
                    `INSERT INTO public.${tables.v2AuditEvents}
                    (id, actor_id, action, metadata) VALUES
                    (?, ?, 'AUTHORIZATION_DECISION',
                     jsonb_build_object('bindingVersion', 9223372036854775808))`,
                    [randomUUID(), "oidc:" + "a".repeat(64)]
                )
            )
        );

        const canaries = [
            "access-canary",
            "id-token-canary",
            "refresh-canary",
            "cookie-canary",
            "csrf-canary",
            "query-canary",
            "email@example.test",
            "user-name-canary",
        ];
        for (const canary of canaries)
            await expectRejected(
                database.transaction((savepoint) =>
                    savepoint(tables.v2AuditEvents).insert({
                        id: randomUUID(),
                        actor_id: "oidc:" + "a".repeat(64),
                        action: "AUTHORIZATION_DECISION",
                        metadata: {
                            objectKind: "APPLICATION",
                            operation: "APPLICATION_READ",
                            result: "DENIED",
                            role: "DENIED",
                            source: "NONE",
                            reason: canary,
                        },
                    })
                )
            );
        const retained = JSON.stringify(
            await database(tables.v2AuditEvents).select()
        );
        for (const canary of canaries) expect(retained).not.to.include(canary);
    });

    it("TM-AUD-01 qualifies a LOGIN combined role and rejects every excess capability", async () => {
        const runtimeRole = `v2_authz_runtime_${process.pid}_${Date.now()}`;
        const membershipRole = `${runtimeRole}_member`;
        const password = randomBytes(24).toString("base64url");
        const roleUrl = new URL(postgresUrl);
        roleUrl.pathname = `/${databaseName}`;
        roleUrl.username = runtimeRole;
        roleUrl.password = password;
        const options = {
            clientId: "control",
            configurationUrl:
                "https://idp.example/.well-known/openid-configuration",
            expectedIssuer: "https://idp.example",
            redirectUri: "https://portal.example/api/v2/auth/callback",
            portalOrigin: "https://portal.example",
            primaryKeyId: "primary",
            encryptionKeys: [{ id: "primary", key: Buffer.alloc(32, 7) }],
        };
        const verifyLoginRole = async (): Promise<void> => {
            const connection = createPostgresKnex(roleUrl.toString());
            const sessionService = new V2OidcSessions(connection, options);
            const authorizationService = new V2Authorization(connection, {
                administratorGroupIds: [administratorGroup],
                requiredClaimsVersion: 1,
            });
            const publicationQueue = new V2PublicationQueue(connection);
            try {
                await sessionService.verifyReady();
                await authorizationService.verifyReady();
                await publicationQueue.verifyReady("CONTROL");
            } finally {
                await sessionService.destroy();
            }
        };
        await rootDatabase.raw("REVOKE CREATE ON SCHEMA public FROM PUBLIC");
        await rootDatabase.raw(`CREATE ROLE ${runtimeRole}
            LOGIN PASSWORD '${password}'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`);
        await rootDatabase.raw(`CREATE ROLE ?? NOLOGIN`, [membershipRole]);
        try {
            await rootDatabase.raw(`
                GRANT USAGE ON SCHEMA public TO ${runtimeRole};
                GRANT EXECUTE ON FUNCTION
                    public.v2_begin_oidc_login(uuid,text,text,text,bytea,bytea,text,text,text,integer),
                    public.v2_consume_oidc_login(uuid,text),
                    public.v2_create_or_replace_session(uuid,uuid,text,text,jsonb,text,text,bytea,bytea,integer,integer),
                    public.v2_read_session(uuid), public.v2_use_session(uuid,integer),
                    public.v2_rotate_session_envelope(uuid,text,text,bytea,bytea),
                    public.v2_revoke_session(uuid,text),
                    public.v2_cleanup_auth_state(bigint,integer),
                    public.v2_initialize_authorization_policy(text[],bigint,text),
                    public.v2_authorization_policy_identity(),
                    public.v2_authorize_operation(uuid,uuid,text[],bigint,uuid,text),
                    public.v2_replace_bindings(uuid,uuid,text[],bigint,uuid,bigint,text,text,jsonb),
                    public.v2_request_publication(uuid,uuid,text,uuid,uuid,uuid,uuid,uuid,text[],bigint,text,text),
                    public.v2_publication_operation(uuid)
                TO ${runtimeRole}
            `);
            await verifyLoginRole();
            await rootDatabase.raw(
                `REVOKE EXECUTE ON FUNCTION public.v2_publication_operation(uuid) FROM ${runtimeRole}`
            );
            await expectRejected(
                verifyLoginRole(),
                "publication control PostgreSQL identity is not least privilege"
            );
            await rootDatabase.raw(
                `GRANT EXECUTE ON FUNCTION public.v2_publication_operation(uuid) TO ${runtimeRole}`
            );
            await verifyLoginRole();

            for (const [grant, revoke] of [
                [
                    `GRANT SELECT ON public.${tables.v2Bindings} TO ${runtimeRole}`,
                    `REVOKE SELECT ON public.${tables.v2Bindings} FROM ${runtimeRole}`,
                ],
                [
                    `GRANT SELECT ON public.${tables.v2ReleaseJobs} TO ${runtimeRole}`,
                    `REVOKE SELECT ON public.${tables.v2ReleaseJobs} FROM ${runtimeRole}`,
                ],
                [
                    `GRANT UPDATE (claims) ON public.${tables.v2Sessions} TO ${runtimeRole}`,
                    `REVOKE UPDATE (claims) ON public.${tables.v2Sessions} FROM ${runtimeRole}`,
                ],
                [
                    `GRANT CREATE ON DATABASE ${databaseName} TO ${runtimeRole}`,
                    `REVOKE CREATE ON DATABASE ${databaseName} FROM ${runtimeRole}`,
                ],
                [
                    `GRANT ${membershipRole} TO ${runtimeRole}`,
                    `REVOKE ${membershipRole} FROM ${runtimeRole}`,
                ],
                [
                    `GRANT EXECUTE ON FUNCTION public.v2_claim_release_jobs(text,integer,integer) TO ${runtimeRole}`,
                    `REVOKE EXECUTE ON FUNCTION public.v2_claim_release_jobs(text,integer,integer) FROM ${runtimeRole}`,
                ],
            ]) {
                await rootDatabase.raw(grant);
                await expectRejected(verifyLoginRole(), "least privilege");
                await rootDatabase.raw(revoke);
                await verifyLoginRole();
            }

            const definerSchema = `v2_authz_definer_${process.pid}`;
            await rootDatabase.raw(`CREATE SCHEMA ${definerSchema}`);
            await rootDatabase.raw(`
                CREATE FUNCTION ${definerSchema}.unrelated_runtime_power()
                RETURNS integer LANGUAGE sql SECURITY DEFINER
                SET search_path = pg_catalog AS 'SELECT 1'
            `);
            await rootDatabase.raw(
                `GRANT USAGE ON SCHEMA ${definerSchema} TO ${runtimeRole}`
            );
            await rootDatabase.raw(
                `GRANT EXECUTE ON FUNCTION ${definerSchema}.unrelated_runtime_power() TO ${runtimeRole}`
            );
            await expectRejected(verifyLoginRole(), "least privilege");
            await rootDatabase.raw(
                `REVOKE EXECUTE ON FUNCTION ${definerSchema}.unrelated_runtime_power() FROM ${runtimeRole}`
            );
            await rootDatabase.raw(
                `REVOKE USAGE ON SCHEMA ${definerSchema} FROM ${runtimeRole}`
            );
            await rootDatabase.raw(`DROP SCHEMA ${definerSchema} CASCADE`);
            await verifyLoginRole();

            const ownedSchema = `${runtimeRole}_owned`;
            await rootDatabase.raw(
                `CREATE SCHEMA ${ownedSchema} AUTHORIZATION ${runtimeRole}`
            );
            await expectRejected(verifyLoginRole(), "least privilege");
            await rootDatabase.raw(`DROP SCHEMA ${ownedSchema}`);

            await rootDatabase.raw(`ALTER ROLE ${runtimeRole} CREATEDB`);
            await expectRejected(verifyLoginRole(), "least privilege");
            await rootDatabase.raw(`ALTER ROLE ${runtimeRole} NOCREATEDB`);

            await rootDatabase.raw(
                `REVOKE EXECUTE ON FUNCTION public.v2_use_session(uuid,integer) FROM ${runtimeRole}`
            );
            await expectRejected(verifyLoginRole(), "least privilege");
            await rootDatabase.raw(
                `GRANT EXECUTE ON FUNCTION public.v2_use_session(uuid,integer) TO ${runtimeRole}`
            );
            await rootDatabase.raw(
                `REVOKE EXECUTE ON FUNCTION public.v2_authorize_operation(uuid,uuid,text[],bigint,uuid,text) FROM ${runtimeRole}`
            );
            await expectRejected(verifyLoginRole(), "least privilege");
            await rootDatabase.raw(
                `GRANT EXECUTE ON FUNCTION public.v2_authorize_operation(uuid,uuid,text[],bigint,uuid,text) TO ${runtimeRole}`
            );
            await verifyLoginRole();

            const runtimeConnection = createPostgresKnex(roleUrl.toString());
            try {
                for (const operation of [
                    runtimeConnection(tables.v2AuditEvents).update({
                        action: "DIRECT",
                    }),
                    runtimeConnection(tables.v2AuditEvents).del(),
                    runtimeConnection.raw(
                        `TRUNCATE public.${tables.v2AuditEvents}`
                    ),
                ])
                    await expectRejected(operation);
            } finally {
                await runtimeConnection.destroy();
            }
        } finally {
            await rootDatabase.raw(`DROP OWNED BY ${runtimeRole}`);
            await rootDatabase.raw(`DROP ROLE IF EXISTS ${runtimeRole}`);
            await rootDatabase.raw(`DROP ROLE IF EXISTS ${membershipRole}`);
        }
    });
});
