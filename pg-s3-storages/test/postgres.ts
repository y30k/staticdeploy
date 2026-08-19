import { IHealthCheckResult } from "@staticdeploy/core";
import { expect } from "chai";
import { Knex } from "knex";
import { createHash, randomBytes } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import PgS3Storages from "../src";
import { StorageSetupError } from "../src/common/errors";
import tables from "../src/common/tables";
import {
    createPostgresKnex,
    defaultPostgresClientOptions,
} from "../src/postgres";

const postgresUrl =
    process.env.POSTGRES_TEST_URL ??
    "postgres://postgres:password@127.0.0.1:5432/postgres";
let productionMigrationConfig: Knex.MigratorConfig;
let fallbackMigrationDirectory: string | undefined;
const legacyFixtures = {
    post01: {
        file: "legacy-post-01.sql",
        sha256: "9160cf4433e4936abab124da6c3c05e68c5d97220e6fef518f2f5cd282cee3be",
    },
    post02: {
        file: "legacy-post-02.sql",
        sha256: "84ebe1de070adcb7cf9533b8f4c6b16b7d155e277d7878f24bcbeecee6870213",
    },
} as const;

interface LegacySnapshot {
    hash: string;
    rows: Record<string, unknown[]>;
    foreignKeys: unknown[];
    migrationHistory: unknown[];
    migrationLock: unknown[];
}

describe("Knex 3 PostgreSQL migration and failure contracts", () => {
    let admin: Knex;

    before(async () => {
        const prepared = await prepareProductionMigrationConfig();
        productionMigrationConfig = prepared.config;
        fallbackMigrationDirectory = prepared.fallbackDirectory;
        admin = createPostgresKnex(postgresUrl);
    });

    after(async () => {
        try {
            await admin.destroy();
        } finally {
            if (fallbackMigrationDirectory !== undefined) {
                await rm(fallbackMigrationDirectory, {
                    recursive: true,
                    force: true,
                });
            }
        }
    });

    it("SCH-01 migrates a truly empty schema and reruns idempotently", async () => {
        await withDisposableDatabase(admin, async (database) => {
            expect(await applicationTables(database)).to.deep.equal([]);

            const first = await database.migrate.latest(
                productionMigrationConfig
            );
            expect(first[1]).to.deep.equal([
                "00.js",
                "01.js",
                "02.js",
                "03.js",
                "04.js",
            ]);
            expect(await applicationTables(database)).to.deep.equal([
                "apps",
                "bundles",
                "entrypoints",
                "groups",
                "operationLogs",
                "users",
                "users_groups",
                "v2_applications",
                "v2_audit_events",
                "v2_bindings",
                "v2_idempotency",
                "v2_outbox_transition_guards",
                "v2_publication_guards",
                "v2_publication_outbox",
                "v2_release_job_transition_guards",
                "v2_release_jobs",
                "v2_releases",
                "v2_sessions",
                "v2_upload_files",
            ]);
            expect(await migrationNames(database)).to.deep.equal([
                "00.js",
                "01.js",
                "02.js",
                "03.js",
                "04.js",
            ]);

            const foreignKeys = await database(
                "information_schema.table_constraints"
            )
                .select("table_name")
                .where({
                    constraint_schema: "public",
                    constraint_type: "FOREIGN KEY",
                })
                .orderBy("table_name");
            expect(foreignKeys.map((row) => row.table_name)).to.deep.equal([
                "entrypoints",
                "entrypoints",
                "users_groups",
                "users_groups",
                "v2_applications",
                "v2_applications",
                "v2_audit_events",
                "v2_audit_events",
                "v2_bindings",
                "v2_outbox_transition_guards",
                "v2_publication_guards",
                "v2_publication_outbox",
                "v2_publication_outbox",
                "v2_release_job_transition_guards",
                "v2_release_jobs",
                "v2_releases",
                "v2_upload_files",
            ]);

            const second = await database.migrate.latest(
                productionMigrationConfig
            );
            expect(second[1]).to.deep.equal([]);
            expect(await migrationNames(database)).to.deep.equal([
                "00.js",
                "01.js",
                "02.js",
                "03.js",
                "04.js",
            ]);
        });
    });

    it("SCH-02 upgrades a captured post-02 schema without changing legacy rows or FKs", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await installLegacyFixture(database, "post02");
            const before = await legacySnapshot(database);

            const result = await database.migrate.latest(
                productionMigrationConfig
            );
            const after = await legacySnapshot(database);

            expect(result[1]).to.deep.equal(["03.js", "04.js"]);
            expect(await migrationNames(database)).to.deep.equal([
                "00.js",
                "01.js",
                "02.js",
                "03.js",
                "04.js",
            ]);
            expect(after.rows).to.deep.equal(before.rows);
            expect(after.foreignKeys).to.deep.equal(before.foreignKeys);
            const linkedEntrypoint = await database(tables.entrypoints)
                .join(
                    tables.apps,
                    `${tables.entrypoints}.appId`,
                    `${tables.apps}.id`
                )
                .join(
                    tables.bundles,
                    `${tables.entrypoints}.bundleId`,
                    `${tables.bundles}.id`
                )
                .first(`${tables.entrypoints}.id`);
            const linkedMembership = await database(tables.usersAndGroups)
                .join(
                    tables.users,
                    `${tables.usersAndGroups}.userId`,
                    `${tables.users}.id`
                )
                .join(
                    tables.groups,
                    `${tables.usersAndGroups}.groupId`,
                    `${tables.groups}.id`
                )
                .first(`${tables.usersAndGroups}.userId`);
            expect(linkedEntrypoint.id).to.equal("entrypoint-1");
            expect(linkedMembership.userId).to.equal("user-1");
        });
    });

    it("migrates a captured pre-02 production history exactly once", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await installLegacyFixture(database, "post01");

            const first = await database.migrate.latest(
                productionMigrationConfig
            );
            expect(first[1]).to.deep.equal(["02.js", "03.js", "04.js"]);
            expect((await database(tables.groups).first()).roles).to.deep.equal(
                ["app-manager:application-one", "root"]
            );

            const second = await database.migrate.latest(
                productionMigrationConfig
            );
            expect(second[1]).to.deep.equal([]);
            expect((await database(tables.groups).first()).roles).to.deep.equal(
                ["app-manager:application-one", "root"]
            );
            expect(await migrationNames(database)).to.deep.equal([
                "00.js",
                "01.js",
                "02.js",
                "03.js",
                "04.js",
            ]);
        });
    });

    it("SCH-01 reverses and reapplies additive migrations 04 and 03", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            await database(tables.apps).insert(appRow());

            const down04 = await database.migrate.down(
                productionMigrationConfig
            );
            expect(down04[1]).to.deep.equal(["04.js"]);
            for (const table of v2OperationalTableNames()) {
                expect(await database.schema.hasTable(table)).to.equal(false);
            }
            for (const table of v2TableNames()) {
                expect(await database.schema.hasTable(table)).to.equal(true);
            }

            const down03 = await database.migrate.down(
                productionMigrationConfig
            );
            expect(down03[1]).to.deep.equal(["03.js"]);
            expect(await database.schema.hasTable(tables.apps)).to.equal(true);
            expect(await database(tables.apps).select("id")).to.deep.equal([
                { id: "app-1" },
            ]);
            for (const table of v2TableNames()) {
                expect(await database.schema.hasTable(table)).to.equal(false);
            }

            const reapply = await database.migrate.latest(
                productionMigrationConfig
            );
            expect(reapply[1]).to.deep.equal(["03.js", "04.js"]);
            for (const table of [
                ...v2TableNames(),
                ...v2OperationalTableNames(),
            ]) {
                expect(await database.schema.hasTable(table)).to.equal(true);
            }
        });
    });

    it("SCH-01 refuses destructive rollback when v2 history exists", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const application = v2ApplicationRow();
            const releaseId = "10000000-0000-4000-8000-000000000000";
            await database(tables.v2Applications).insert(application);
            await database(tables.v2Releases).insert(
                v2ReadyReleaseRow(releaseId)
            );
            await database(tables.v2AuditEvents).insert({
                id: "30000000-0000-4000-8000-000000000000",
                actor_id: "actor-rollback-test",
                action: "RELEASE_READY",
                application_id: application.id,
                release_id: releaseId,
                occurred_at: fixtureDate(),
            });
            expect(
                (await database.migrate.down(productionMigrationConfig))[1]
            ).to.deep.equal(["04.js"]);

            await expectDatabaseError(
                database.migrate.down(productionMigrationConfig),
                "expand-only rollback refused"
            );
            expect(await migrationNames(database)).to.deep.equal([
                "00.js",
                "01.js",
                "02.js",
                "03.js",
            ]);
            expect(
                await database(tables.v2Releases)
                    .where({ id: releaseId })
                    .first("state")
            ).to.deep.equal({ state: "READY" });
            expect(
                await database(tables.v2AuditEvents)
                    .where({ release_id: releaseId })
                    .first("action")
            ).to.deep.equal({ action: "RELEASE_READY" });
        });
    });

    it("SCH-01 serializes rollback against concurrent v2 writers", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            expect(
                (await database.migrate.down(productionMigrationConfig))[1]
            ).to.deep.equal(["04.js"]);
            const writer = await database.transaction();
            let writerCommitted = false;
            let downSettled = false;
            let downAttempt: Promise<unknown> | undefined;
            try {
                await writer(tables.v2Applications).insert(v2ApplicationRow());
                downAttempt = database.migrate
                    .down(productionMigrationConfig)
                    .then(
                        (result) => {
                            downSettled = true;
                            return result;
                        },
                        (error: unknown) => {
                            downSettled = true;
                            return error;
                        }
                    );

                await new Promise((resolve) => setTimeout(resolve, 150));
                expect(downSettled).to.equal(false);
                await writer.commit();
                writerCommitted = true;
                const downResult = await downAttempt;
                expect(downResult).to.be.instanceOf(Error);
                expect(errorText(downResult)).to.include(
                    "expand-only rollback refused"
                );
            } catch (error) {
                if (!writerCommitted) {
                    await writer.rollback();
                }
                await downAttempt;
                throw error;
            }

            expect(
                await database(tables.v2Applications).first("id")
            ).to.deep.equal({ id: v2ApplicationRow().id });
            expect(await migrationNames(database)).to.include("03.js");
        });
    });

    it("SCH-03 serializes same-second version labels per application", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            await database(tables.v2Applications).insert(v2ApplicationRow());
            const releases = [
                "10000000-0000-4000-8000-000000000001",
                "10000000-0000-4000-8000-000000000002",
                "10000000-0000-4000-8000-000000000003",
            ];
            await database(tables.v2Releases).insert(
                releases.map((id) => v2ReadyReleaseRow(id))
            );
            const publishedAt = new Date("2026-08-17T13:31:22.000Z");

            await expectDatabaseError(
                database.raw(
                    "select public.v2_claim_release_version(?, ?) as label",
                    [releases[0], null]
                ),
                "publication timestamp is required"
            );
            await expectDatabaseError(
                database.raw(
                    "select public.v2_claim_release_version(?, ?) as label",
                    ["10000000-0000-4000-8000-000000000099", publishedAt]
                ),
                "READY release not found"
            );
            const processingReleaseId = "10000000-0000-4000-8000-000000000098";
            await database(tables.v2Releases).insert({
                ...v2ReadyReleaseRow(processingReleaseId),
                state: "PROCESSING",
                default_path: null,
                manifest_digest: null,
                finalized_at: null,
            });
            await expectDatabaseError(
                database.raw(
                    "select public.v2_claim_release_version(?, ?) as label",
                    [processingReleaseId, publishedAt]
                ),
                "READY release not found"
            );

            const claimed = await Promise.all(
                releases.map(async (id) => {
                    const result = await database.raw(
                        "select public.v2_claim_release_version(?, ?) as label",
                        [id, publishedAt]
                    );
                    return result.rows[0].label as string;
                })
            );

            expect(claimed.sort()).to.deep.equal([
                "2026.08.17-13.31.22",
                "2026.08.17-13.31.22-2",
                "2026.08.17-13.31.22-3",
            ]);
            const stored = await database(tables.v2Releases)
                .select("version_label", "published_at")
                .whereNotNull("published_at")
                .orderBy("version_label");
            expect(stored.map((row) => row.version_label)).to.deep.equal([
                "2026.08.17-13.31.22",
                "2026.08.17-13.31.22-2",
                "2026.08.17-13.31.22-3",
            ]);
            expect(
                stored.every(
                    (row) =>
                        new Date(row.published_at).toISOString() ===
                        publishedAt.toISOString()
                )
            ).to.equal(true);

            const repeat = await database.raw(
                "select public.v2_claim_release_version(?, ?) as label",
                [releases[0], new Date("2027-01-01T00:00:00.000Z")]
            );
            expect(repeat.rows[0].label).to.equal(
                (
                    await database(tables.v2Releases)
                        .where({ id: releases[0] })
                        .first("version_label")
                ).version_label
            );

            const directReleaseId = "10000000-0000-4000-8000-000000000004";
            await database(tables.v2Releases).insert(
                v2ReadyReleaseRow(directReleaseId)
            );
            await expectDatabaseError(
                database(tables.v2Releases)
                    .where({ id: directReleaseId })
                    .update({
                        published_at: publishedAt,
                        version_label: "2026.08.17-13.31.22-99",
                    }),
                "publication identity must use v2_claim_release_version"
            );
            const directClaim = await database.raw(
                "select public.v2_claim_release_version(?, ?) as label",
                [directReleaseId, publishedAt]
            );
            expect(directClaim.rows[0].label).to.equal("2026.08.17-13.31.22-4");
            await expectDatabaseError(
                database(tables.v2Releases)
                    .where({ id: directReleaseId })
                    .update({
                        published_at: new Date("2027-01-01T00:00:00.000Z"),
                        version_label: "2027.01.01-00.00.00",
                    }),
                "release publication identity is immutable"
            );
            await expectDatabaseError(
                database(tables.v2Releases).insert({
                    ...v2ReadyReleaseRow(
                        "10000000-0000-4000-8000-000000000005"
                    ),
                    published_at: publishedAt,
                    version_label: "2026.08.17-13.31.22-5",
                }),
                "publication identity must be assigned after READY finalization"
            );
        });
    });

    it("SCH-04 enforces the publication privilege boundary for non-owners", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const application = v2ApplicationRow();
            const releaseId = "10000000-0000-4000-8000-000000000006";
            const role = `m302_${randomBytes(8).toString("hex")}`;
            await database(tables.v2Applications).insert(application);
            await database(tables.v2Releases).insert(
                v2ReadyReleaseRow(releaseId)
            );
            await database.raw("create role ?? nologin", [role]);
            try {
                await database.raw("grant usage on schema public to ??", [
                    role,
                ]);
                await database.raw(
                    `grant select on public.${tables.v2Releases} to ??`,
                    [role]
                );
                await database.raw(
                    `grant update (published_at, version_label) on public.${tables.v2Releases} to ??`,
                    [role]
                );

                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction.raw(
                            `select * from public.${tables.v2PublicationGuards}`
                        );
                    }),
                    `permission denied for table ${tables.v2PublicationGuards}`
                );
                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction.raw(
                            "select public.v2_claim_release_version(?, ?) as label",
                            [releaseId, fixtureDate()]
                        );
                    }),
                    "permission denied for function v2_claim_release_version"
                );
                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction.raw(
                            `update public.${tables.v2Releases}
                                set published_at = ?, version_label = ?
                              where id = ?`,
                            [fixtureDate(), "2021.11.24-23.19.33", releaseId]
                        );
                    }),
                    "publication identity must use v2_claim_release_version"
                );

                await database.raw(
                    "grant execute on function public.v2_claim_release_version(uuid, timestamptz) to ??",
                    [role]
                );
                let claimedLabel: string | undefined;
                await database.transaction(async (transaction) => {
                    await transaction.raw("set local role ??", [role]);
                    const claimed = await transaction.raw(
                        "select public.v2_claim_release_version(?, ?) as label",
                        [releaseId, fixtureDate()]
                    );
                    claimedLabel = claimed.rows[0].label as string;
                });
                expect(claimedLabel).to.equal("2021.11.24-23.19.33");
            } finally {
                await database.raw("drop owned by ??", [role]);
                await database.raw("drop role ??", [role]);
            }
        });
    });

    it("SCH-04 enforces READY, upload, audit, state, path, role, and FK guards", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const application = v2ApplicationRow();
            const releaseId = "10000000-0000-4000-8000-000000000010";
            const uploadId = "20000000-0000-4000-8000-000000000010";
            await database(tables.v2Applications).insert(application);
            await database(tables.v2Releases).insert({
                ...v2ReadyReleaseRow(releaseId),
                state: "PROCESSING",
                default_path: null,
                manifest_digest: null,
                finalized_at: null,
            });
            await database(tables.v2UploadFiles).insert({
                id: uploadId,
                release_id: releaseId,
                state: "OBSERVED",
                declared_path: "nested/app.html",
                declared_size: 12,
                observed_path: "nested/app.html",
                observed_size: 12,
                observed_digest: "a".repeat(64),
                observed_at: fixtureDate(),
            });
            await expectDatabaseError(
                database(tables.v2Releases)
                    .where({ id: releaseId })
                    .update({
                        state: "READY",
                        default_path: "nested/app.html",
                        manifest_digest: "b".repeat(64),
                        finalized_at: fixtureDate(),
                        published_at: fixtureDate(),
                        version_label: "2021.11.24-23.19.33",
                    }),
                "release must already be READY before publication"
            );
            await database(tables.v2Releases)
                .where({ id: releaseId })
                .update({
                    state: "READY",
                    default_path: "nested/app.html",
                    manifest_digest: "b".repeat(64),
                    finalized_at: fixtureDate(),
                });
            await database(tables.v2AuditEvents).insert({
                id: "30000000-0000-4000-8000-000000000010",
                actor_id: "actor-1",
                action: "RELEASE_READY",
                application_id: application.id,
                release_id: releaseId,
                occurred_at: fixtureDate(),
            });

            await expectDatabaseError(
                database(tables.v2Releases)
                    .where({ id: releaseId })
                    .update({ manifest_digest: "c".repeat(64) }),
                "READY release content fields are immutable"
            );
            await expectDatabaseError(
                database(tables.v2Releases).where({ id: releaseId }).delete(),
                "READY release is immutable"
            );
            await expectDatabaseError(
                database(tables.v2UploadFiles)
                    .where({ id: uploadId })
                    .update({ observed_size: 13 }),
                "READY release upload declarations are immutable"
            );
            await expectDatabaseError(
                database(tables.v2UploadFiles).insert({
                    id: "20000000-0000-4000-8000-000000000099",
                    release_id: releaseId,
                    declared_path: "late.html",
                    declared_size: 1,
                }),
                "READY release upload declarations are immutable"
            );
            await expectDatabaseError(
                database(tables.v2UploadFiles).where({ id: uploadId }).delete(),
                "READY release upload declarations are immutable"
            );
            await expectDatabaseError(
                database.raw(`truncate table public.${tables.v2UploadFiles}`),
                "upload declarations cannot be truncated"
            );
            await database.raw(
                "create temporary table v2_releases (id uuid primary key, state text)"
            );
            await expectDatabaseError(
                database.raw(
                    "update public.v2_upload_files set observed_size = ? where id = ?",
                    [13, uploadId]
                ),
                "READY release upload declarations are immutable"
            );
            await database.raw("drop table pg_temp.v2_releases");
            await expectDatabaseError(
                database(tables.v2AuditEvents)
                    .where({ application_id: application.id })
                    .update({ action: "ALTERED" }),
                "audit events are append-only"
            );
            await expectDatabaseError(
                database(tables.v2AuditEvents)
                    .where({ application_id: application.id })
                    .delete(),
                "audit events are append-only"
            );
            await expectDatabaseError(
                database.raw(`truncate table ${tables.v2AuditEvents}`),
                "audit events are append-only"
            );
            await database(tables.v2Applications)
                .where({ id: application.id })
                .update({ desired_generation: 2 });
            await expectDatabaseError(
                database(tables.v2Applications)
                    .where({ id: application.id })
                    .update({ desired_generation: 1 }),
                "application routing generations cannot decrease"
            );
            await expectDatabaseError(
                database(tables.v2Applications)
                    .where({ id: application.id })
                    .update({ served_generation: 1 }),
                "served projection must use v2_acknowledge_publication"
            );
            await expectDatabaseError(
                database(tables.v2Bindings).insert({
                    id: "40000000-0000-4000-8000-000000000010",
                    application_id: application.id,
                    group_id: "group-1",
                    role: "ADMINISTRATOR",
                    created_by: "actor-1",
                }),
                "v2_bindings_role_check"
            );
            const processingReleaseId = "10000000-0000-4000-8000-000000000011";
            await database(tables.v2Releases).insert({
                ...v2ReadyReleaseRow(processingReleaseId),
                state: "PROCESSING",
                default_path: null,
                manifest_digest: null,
                finalized_at: null,
            });
            await expectDatabaseError(
                database(tables.v2UploadFiles)
                    .where({ id: uploadId })
                    .update({ release_id: processingReleaseId }),
                "READY release upload declarations are immutable"
            );
            await expectDatabaseError(
                database(tables.v2UploadFiles).insert({
                    id: "20000000-0000-4000-8000-000000000011",
                    release_id: processingReleaseId,
                    declared_path: "/escape.html",
                    declared_size: 1,
                }),
                "v2_upload_files_declared_path_check"
            );
            await expectDatabaseError(
                database(tables.v2Releases).insert({
                    id: "10000000-0000-4000-8000-000000000099",
                    application_id: "00000000-0000-4000-8000-000000000099",
                    state: "PENDING_UPLOAD",
                }),
                "v2_releases_application_fk"
            );

            const otherApplication = {
                ...v2ApplicationRow(),
                id: "00000000-0000-4000-8000-000000000011",
                name: "application-v2-two",
                routing_id: "00000000-0000-4000-8000-000000000012",
            };
            const otherReleaseId = "10000000-0000-4000-8000-000000000013";
            await database(tables.v2Applications).insert(otherApplication);
            await database(tables.v2Releases).insert({
                ...v2ReadyReleaseRow(otherReleaseId),
                application_id: otherApplication.id,
            });
            await expectDatabaseError(
                database(tables.v2Applications)
                    .where({ id: application.id })
                    .update({
                        desired_current_release_id: otherReleaseId,
                        desired_generation: 3,
                    }),
                "v2_applications_desired_release_fk"
            );
            await expectDatabaseError(
                database(tables.v2AuditEvents).insert({
                    id: "30000000-0000-4000-8000-000000000011",
                    actor_id: "actor-1",
                    action: "RELEASE_READY",
                    application_id: application.id,
                    release_id: otherReleaseId,
                    occurred_at: fixtureDate(),
                }),
                "v2_audit_events_release_fk"
            );
            await database(tables.v2AuditEvents).insert({
                id: "30000000-0000-4000-8000-000000000012",
                actor_id: "actor-global",
                action: "AUTHENTICATION_SUCCEEDED",
                occurred_at: fixtureDate(),
            });
        });
    });

    it("SCH-04 serializes upload mutation before READY finalization", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const application = v2ApplicationRow();
            const releaseId = "10000000-0000-4000-8000-000000000012";
            const uploadId = "20000000-0000-4000-8000-000000000012";
            await database(tables.v2Applications).insert(application);
            await database(tables.v2Releases).insert({
                ...v2ReadyReleaseRow(releaseId),
                state: "PROCESSING",
                default_path: null,
                manifest_digest: null,
                finalized_at: null,
            });

            const uploadTransaction = await database.transaction();
            let uploadCommitted = false;
            let transitionSettled = false;
            let readyTransition: Promise<void> | undefined;
            try {
                await uploadTransaction(tables.v2UploadFiles).insert({
                    id: uploadId,
                    release_id: releaseId,
                    state: "OBSERVED",
                    declared_path: "index.html",
                    declared_size: 12,
                    observed_path: "index.html",
                    observed_size: 12,
                    observed_digest: "a".repeat(64),
                    observed_at: fixtureDate(),
                });
                readyTransition = database(tables.v2Releases)
                    .where({ id: releaseId })
                    .update({
                        state: "READY",
                        default_path: "index.html",
                        manifest_digest: "b".repeat(64),
                        finalized_at: fixtureDate(),
                    })
                    .then(() => {
                        transitionSettled = true;
                    });

                await new Promise((resolve) => setTimeout(resolve, 150));
                expect(transitionSettled).to.equal(false);
                await uploadTransaction.commit();
                uploadCommitted = true;
                await readyTransition;
            } catch (error) {
                if (!uploadCommitted) {
                    await uploadTransaction.rollback();
                }
                await readyTransition?.catch(() => undefined);
                throw error;
            }

            await expectDatabaseError(
                database(tables.v2UploadFiles)
                    .where({ id: uploadId })
                    .update({ observed_size: 13 }),
                "READY release upload declarations are immutable"
            );
        });
    });

    it("SCH-05 uses bounded application and audit indexes", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            await database.raw(`
                insert into public.${tables.v2Applications}
                    (id, name, routing_id, created_at, updated_at)
                select
                    ('00000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    'application-' || lpad(i::text, 4, '0'),
                    ('10000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    timestamptz '2026-08-17T00:00:00Z' + i * interval '1 second',
                    timestamptz '2026-08-17T00:00:00Z' + i * interval '1 second'
                from generate_series(1, 2000) as generated(i);

                insert into public.${tables.v2AuditEvents}
                    (id, actor_id, action, application_id, occurred_at)
                select
                    ('30000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    'actor-' || lpad((i % 100)::text, 3, '0'),
                    case i % 4
                        when 0 then 'APPLICATION_CREATED'
                        when 1 then 'APPLICATION_VIEWED'
                        when 2 then 'RELEASE_LISTED'
                        else 'AUDIT_VIEWED'
                    end,
                    ('00000000-0000-4000-8000-' || lpad(((i % 2000) + 1)::text, 12, '0'))::uuid,
                    timestamptz '2026-08-17T00:00:00Z' + i * interval '1 second'
                from generate_series(1, 20000) as generated(i);

                analyze public.${tables.v2Applications};
                analyze public.${tables.v2AuditEvents};
            `);

            const applicationPlan = await explainText(
                database,
                `select id from public.${tables.v2Applications}
                  where status = 'ACTIVE'
                  order by created_at desc, id desc
                  limit 50`
            );
            expect(applicationPlan).to.include(
                "v2_applications_status_created_idx"
            );

            const applicationSearchPlan = await explainText(
                database,
                `select id from public.${tables.v2Applications}
                  where lower(name) like 'application-019%'
                  order by lower(name), id
                  limit 20`
            );
            expect(applicationSearchPlan).to.include(
                "v2_applications_name_search_idx"
            );

            const applicationId = "00000000-0000-4000-8000-000000000001";
            const applicationAuditPlan = await explainText(
                database,
                `select id from public.${tables.v2AuditEvents}
                  where application_id = '${applicationId}'
                  order by occurred_at desc, id desc
                  limit 100`
            );
            expect(applicationAuditPlan).to.include(
                "v2_audit_events_application_time_idx"
            );

            const actorAuditPlan = await explainText(
                database,
                `select id from public.${tables.v2AuditEvents}
                  where actor_id = 'actor-001'
                    and occurred_at >= timestamptz '2026-08-17T04:00:00Z'
                  order by occurred_at desc, id desc
                  limit 100`
            );
            expect(actorAuditPlan).to.include("v2_audit_events_actor_time_idx");

            const actionAuditPlan = await explainText(
                database,
                `select id from public.${tables.v2AuditEvents}
                  where action = 'RELEASE_LISTED'
                  order by occurred_at desc, id desc
                  limit 100`
            );
            expect(actionAuditPlan).to.include(
                "v2_audit_events_action_time_idx"
            );

            const timeAuditPlan = await explainText(
                database,
                `select id from public.${tables.v2AuditEvents}
                  where occurred_at >= timestamptz '2026-08-17T05:30:00Z'
                  order by occurred_at desc, id desc
                  limit 100`
            );
            expect(timeAuditPlan).to.include("v2_audit_events_time_idx");
        });
    });

    it("M3-03 refuses operational rollback with retained data and concurrent writers", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const now = new Date();
            await database(tables.v2Sessions).insert(
                v2SessionRow("50000000-0000-4000-8000-000000000001", now)
            );
            await expectDatabaseError(
                database.migrate.down(productionMigrationConfig),
                "migration 04 contains retained v2 operational data"
            );
            expect(await migrationNames(database)).to.include("04.js");
            expect(
                await database(tables.v2Sessions).first("subject_id")
            ).to.deep.equal({ subject_id: "subject-1" });
        });

        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const writer = await database.transaction();
            let writerCommitted = false;
            let downSettled = false;
            let downAttempt: Promise<unknown> | undefined;
            try {
                await writer(tables.v2Idempotency).insert(
                    v2IdempotencyRow(
                        "60000000-0000-4000-8000-000000000001",
                        new Date()
                    )
                );
                downAttempt = database.migrate
                    .down(productionMigrationConfig)
                    .then(
                        (result) => {
                            downSettled = true;
                            return result;
                        },
                        (error: unknown) => {
                            downSettled = true;
                            return error;
                        }
                    );
                await new Promise((resolve) => setTimeout(resolve, 150));
                expect(downSettled).to.equal(false);
                await writer.commit();
                writerCommitted = true;
                const result = await downAttempt;
                expect(result).to.be.instanceOf(Error);
                expect(errorText(result)).to.include(
                    "expand-only rollback refused"
                );
            } catch (error) {
                if (!writerCommitted) await writer.rollback();
                await downAttempt;
                throw error;
            }
            expect(
                await database(tables.v2Idempotency).first("actor_id")
            ).to.deep.equal({ actor_id: "actor-1" });
        });
    });

    it("M3-03 enforces session envelope, expiry, version, and revocation guards", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const now = new Date();
            const activeId = "50000000-0000-4000-8000-000000000010";
            await database(tables.v2Sessions).insert(
                v2SessionRow(activeId, now)
            );
            await database(tables.v2Sessions)
                .where({ id: activeId })
                .update({
                    claims: JSON.stringify({ groups: ["publisher"] }),
                    claims_version: 2,
                    last_seen_at: now,
                    idle_expires_at: new Date(now.getTime() + 7_200_000),
                });
            await expectDatabaseError(
                database(tables.v2Sessions)
                    .where({ id: activeId })
                    .update({ claims: JSON.stringify({ groups: ["owner"] }) }),
                "session identity and time bounds cannot regress"
            );
            await expectDatabaseError(
                database(tables.v2Sessions)
                    .where({ id: activeId })
                    .update({ claims_version: 1 }),
                "session identity and time bounds cannot regress"
            );
            await expectDatabaseError(
                database(tables.v2Sessions).where({ id: activeId }).delete(),
                "active session cannot be deleted"
            );
            await expectDatabaseError(
                database(tables.v2Sessions).insert({
                    ...v2SessionRow(
                        "50000000-0000-4000-8000-000000000011",
                        now
                    ),
                    token_nonce: Buffer.alloc(4),
                }),
                "v2_sessions_token_envelope_check"
            );
            await expectDatabaseError(
                database(tables.v2Sessions).insert({
                    ...v2SessionRow(
                        "50000000-0000-4000-8000-000000000012",
                        now
                    ),
                    token_key_id: null,
                }),
                "v2_sessions_token_envelope_check"
            );
            await expectDatabaseError(
                database(tables.v2Sessions).insert({
                    ...v2SessionRow(
                        "50000000-0000-4000-8000-000000000013",
                        now
                    ),
                    revoked_at: now,
                    revocation_reason: null,
                }),
                "v2_sessions_revocation_check"
            );
            const expiredId = "50000000-0000-4000-8000-000000000014";
            await database(tables.v2Sessions).insert({
                ...v2SessionRow(expiredId, now),
                created_at: new Date(now.getTime() - 10_800_000),
                last_seen_at: new Date(now.getTime() - 7_200_000),
                idle_expires_at: new Date(now.getTime() - 3_600_000),
            });
            await expectDatabaseError(
                database(tables.v2Sessions)
                    .where({ id: expiredId })
                    .update({
                        idle_expires_at: new Date(now.getTime() + 3_600_000),
                    }),
                "expired session is immutable"
            );
            await database(tables.v2Sessions).where({ id: expiredId }).delete();
            await database(tables.v2Sessions).where({ id: activeId }).update({
                revoked_at: now,
                revocation_reason: "LOGOUT",
            });
            await expectDatabaseError(
                database(tables.v2Sessions)
                    .where({ id: activeId })
                    .update({ revocation_reason: "ALTERED" }),
                "revoked session is immutable"
            );
            await database(tables.v2Sessions).where({ id: activeId }).delete();
            await expectDatabaseError(
                database.raw(`truncate table public.${tables.v2Sessions}`),
                "sessions cannot be truncated"
            );
        });
    });

    it("M3-03 enforces one immutable idempotency result under concurrency", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const now = new Date();
            const attempts = await Promise.allSettled([
                database(tables.v2Idempotency).insert(
                    v2IdempotencyRow(
                        "60000000-0000-4000-8000-000000000010",
                        now
                    )
                ),
                database(tables.v2Idempotency).insert({
                    ...v2IdempotencyRow(
                        "60000000-0000-4000-8000-000000000011",
                        now
                    ),
                    request_digest: "b".repeat(64),
                }),
            ]);
            expect(
                attempts.filter((result) => result.status === "fulfilled")
            ).to.have.length(1);
            expect(
                attempts.filter((result) => result.status === "rejected")
            ).to.have.length(1);
            const [record] = await database(tables.v2Idempotency);
            expect(record.request_digest).to.be.oneOf([
                "a".repeat(64),
                "b".repeat(64),
            ]);

            const resultIds = [
                "61000000-0000-4000-8000-000000000010",
                "61000000-0000-4000-8000-000000000011",
            ];
            const completions = await Promise.all(
                resultIds.map((resultId) =>
                    database(tables.v2Idempotency)
                        .where({ id: record.id, state: "IN_PROGRESS" })
                        .update({
                            state: "COMPLETED",
                            result_kind: "OPERATION",
                            result_id: resultId,
                            result_status: "SUCCEEDED",
                            completed_at: new Date(now.getTime() + 1_000),
                        })
                )
            );
            expect(completions.sort()).to.deep.equal([0, 1]);
            expect(
                (
                    await database(tables.v2Idempotency)
                        .where({ id: record.id })
                        .first("result_id")
                ).result_id
            ).to.be.oneOf(resultIds);
            await expectDatabaseError(
                database(tables.v2Idempotency)
                    .where({ id: record.id })
                    .update({ result_status: "FAILED" }),
                "completed idempotency result is immutable"
            );
            await expectDatabaseError(
                database(tables.v2Idempotency)
                    .where({ id: record.id })
                    .delete(),
                "unexpired idempotency record cannot be deleted"
            );
            const expiredId = "60000000-0000-4000-8000-000000000012";
            await database(tables.v2Idempotency).insert({
                ...v2IdempotencyRow(expiredId, now),
                actor_id: "actor-expired",
                idempotency_key: "expired-idempotency-key",
                created_at: new Date(now.getTime() - 7_200_000),
                expires_at: new Date(now.getTime() - 3_600_000),
            });
            await expectDatabaseError(
                database(tables.v2Idempotency).where({ id: expiredId }).update({
                    state: "COMPLETED",
                    result_kind: "OPERATION",
                    result_id: "61000000-0000-4000-8000-000000000012",
                    result_status: "SUCCEEDED",
                    completed_at: now,
                }),
                "expired idempotency record is immutable"
            );
            await database(tables.v2Idempotency)
                .where({ id: expiredId })
                .delete();
            await expectDatabaseError(
                database.raw(
                    `truncate table public.${tables.v2Idempotency}, public.${tables.v2PublicationOutbox}, public.${tables.v2OutboxTransitionGuards}`
                ),
                "idempotency records cannot be truncated"
            );
        });
    });

    it("M3-03 serializes release-job leases and preserves terminal state", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const now = new Date();
            await database(tables.v2Applications).insert(v2ApplicationRow());
            const releaseId = "10000000-0000-4000-8000-000000000020";
            await database(tables.v2Releases).insert(
                v2ReadyReleaseRow(releaseId)
            );
            const futureReleaseId = "10000000-0000-4000-8000-000000000022";
            const futureJobId = "70000000-0000-4000-8000-000000000022";
            await database(tables.v2Releases).insert(
                v2ReadyReleaseRow(futureReleaseId)
            );
            await database(tables.v2ReleaseJobs).insert({
                ...v2ReleaseJobRow(futureJobId, futureReleaseId, now),
                next_attempt_at: new Date(now.getTime() + 3_600_000),
            });
            await expectDatabaseError(
                database(tables.v2ReleaseJobs)
                    .where({ id: futureJobId })
                    .update({
                        state: "LEASED",
                        lease_owner: "worker-early",
                        lease_expires_at: new Date(now.getTime() + 7_200_000),
                        attempt_count: 1,
                        lease_version: 1,
                        next_attempt_at: null,
                    }),
                "release job is not due for claim"
            );
            const jobId = "70000000-0000-4000-8000-000000000020";
            await database(tables.v2ReleaseJobs).insert(
                v2ReleaseJobRow(jobId, releaseId, now)
            );
            await expectDatabaseError(
                database(tables.v2ReleaseJobs).insert({
                    id: "70000000-0000-4000-8000-000000000019",
                    release_id: releaseId,
                    kind: "CLEANUP_QUARANTINE",
                    state: "SUCCEEDED",
                    attempt_count: 1,
                    lease_version: 1,
                    next_attempt_at: null,
                    completed_at: now,
                    created_at: now,
                    updated_at: now,
                }),
                "release job must start pending and unclaimed"
            );
            await expectDatabaseError(
                database(tables.v2ReleaseJobs).where({ id: jobId }).update({
                    state: "SUCCEEDED",
                    next_attempt_at: null,
                    completed_at: now,
                }),
                "illegal release job state transition"
            );

            const leaseUntil = new Date(now.getTime() + 3_600_000);
            await expectDatabaseError(
                database(tables.v2ReleaseJobs).where({ id: jobId }).update({
                    state: "LEASED",
                    lease_owner: "worker-unfenced",
                    lease_expires_at: leaseUntil,
                    attempt_count: 1,
                    next_attempt_at: null,
                    updated_at: now,
                }),
                "release job claim must advance attempt and lease version"
            );
            const claims = await Promise.all([
                database(tables.v2ReleaseJobs)
                    .where({ id: jobId, state: "PENDING" })
                    .update({
                        state: "LEASED",
                        lease_owner: "worker-a",
                        lease_expires_at: leaseUntil,
                        attempt_count: 1,
                        lease_version: 1,
                        next_attempt_at: null,
                        updated_at: now,
                    }),
                database(tables.v2ReleaseJobs)
                    .where({ id: jobId, state: "PENDING" })
                    .update({
                        state: "LEASED",
                        lease_owner: "worker-b",
                        lease_expires_at: leaseUntil,
                        attempt_count: 1,
                        lease_version: 1,
                        next_attempt_at: null,
                        updated_at: now,
                    }),
            ]);
            expect(claims.sort()).to.deep.equal([0, 1]);
            await expectDatabaseError(
                database(tables.v2ReleaseJobs).where({ id: jobId }).update({
                    state: "RETRY_WAIT",
                    lease_owner: null,
                    lease_expires_at: null,
                    next_attempt_at: now,
                    last_error_code: "EARLY_RETRY",
                }),
                "leased release job transition must use v2_finish_release_job_attempt"
            );
            await expectDatabaseError(
                database(tables.v2ReleaseJobs)
                    .where({ id: jobId })
                    .update({
                        lease_owner: "worker-c",
                        lease_expires_at: new Date(now.getTime() + 7_200_000),
                        attempt_count: 2,
                        lease_version: 2,
                    }),
                "live release job lease cannot be reclaimed"
            );
            await expectDatabaseError(
                database.raw(
                    "select public.v2_finish_release_job_attempt(?, ?, ?, ?, ?, ?, ?)",
                    [jobId, "worker-a", 1, null, "NULL_OUTCOME", null, null]
                ),
                "release job transition arguments are invalid"
            );
            await database.raw(
                "select public.v2_finish_release_job_attempt(?, ?, ?, ?, ?, ?, ?)",
                [jobId, "worker-a", 1, "RETRY", "EARLY_RETRY", null, null]
            );
            expect(
                await database(tables.v2ReleaseJobs)
                    .where({ id: jobId })
                    .first("state", "attempt_count", "lease_version")
            ).to.deep.equal({
                state: "RETRY_WAIT",
                attempt_count: 1,
                lease_version: "1",
            });
            await database(tables.v2ReleaseJobs)
                .where({ id: jobId, state: "RETRY_WAIT" })
                .update({
                    state: "LEASED",
                    lease_owner: "worker-b",
                    lease_expires_at: new Date(Date.now() + 3_600_000),
                    attempt_count: 2,
                    lease_version: 2,
                    next_attempt_at: null,
                    last_error_code: null,
                    updated_at: new Date(),
                });
            await expectDatabaseError(
                database.raw(
                    "select public.v2_finish_release_job_attempt(?, ?, ?, ?, ?, ?, ?)",
                    [jobId, "worker-a", 1, "SUCCEEDED", null, null, null]
                ),
                "active release job lease fencing does not match"
            );
            await database.raw(
                "select public.v2_finish_release_job_attempt(?, ?, ?, ?, ?, ?, ?)",
                [jobId, "worker-b", 2, "SUCCEEDED", null, null, null]
            );

            const expiredJobId = "70000000-0000-4000-8000-000000000021";
            const expiredUpdatedAt = new Date(now.getTime() - 7_200_000);
            const expiredAt = new Date(now.getTime() - 3_600_000);
            await database(tables.v2ReleaseJobs).insert({
                id: expiredJobId,
                release_id: releaseId,
                kind: "CLEANUP_QUARANTINE",
                state: "PENDING",
                max_attempts: 2,
                next_attempt_at: expiredUpdatedAt,
                created_at: expiredUpdatedAt,
                updated_at: expiredUpdatedAt,
            });
            await database(tables.v2ReleaseJobs)
                .where({ id: expiredJobId })
                .update({
                    state: "LEASED",
                    lease_owner: "worker-old",
                    lease_expires_at: expiredAt,
                    attempt_count: 1,
                    lease_version: 1,
                    next_attempt_at: null,
                    updated_at: expiredUpdatedAt,
                });
            expect(
                await database(tables.v2ReleaseJobs)
                    .where({ id: expiredJobId, state: "LEASED" })
                    .where("lease_expires_at", "<", new Date())
                    .update({
                        lease_owner: "worker-c",
                        lease_expires_at: new Date(now.getTime() + 7_200_000),
                        attempt_count: 2,
                        lease_version: 2,
                        updated_at: now,
                    })
            ).to.equal(1);
            await expectDatabaseError(
                database.raw(
                    "select public.v2_finish_release_job_attempt(?, ?, ?, ?, ?, ?, ?)",
                    [
                        expiredJobId,
                        "worker-c",
                        2,
                        "RETRY",
                        "RETRYABLE_FAILURE",
                        null,
                        null,
                    ]
                ),
                "final release job attempt cannot be retried"
            );
            expect(
                await database(tables.v2ReleaseJobs)
                    .where({
                        id: expiredJobId,
                        state: "LEASED",
                        lease_version: 1,
                    })
                    .update({
                        state: "SUCCEEDED",
                        lease_owner: null,
                        lease_expires_at: null,
                        next_attempt_at: null,
                        completed_at: now,
                        updated_at: now,
                    })
            ).to.equal(0);
            await expectDatabaseError(
                database(tables.v2ReleaseJobs)
                    .where({
                        id: expiredJobId,
                        state: "LEASED",
                        lease_version: 2,
                    })
                    .update({
                        state: "SUCCEEDED",
                        lease_owner: null,
                        lease_expires_at: null,
                        next_attempt_at: null,
                        completed_at: now,
                        updated_at: now,
                    }),
                "leased release job transition must use v2_finish_release_job_attempt"
            );
            await database.raw(
                "select public.v2_finish_release_job_attempt(?, ?, ?, ?, ?, ?, ?)",
                [expiredJobId, "worker-c", 2, "SUCCEEDED", null, null, null]
            );
            await expectDatabaseError(
                database(tables.v2ReleaseJobs)
                    .where({ id: jobId })
                    .update({ state: "FAILED", terminal_reason: "ALTERED" }),
                "terminal release job is immutable"
            );
            await expectDatabaseError(
                database(tables.v2ReleaseJobs).where({ id: jobId }).delete(),
                "release job rows cannot be deleted"
            );
            await expectDatabaseError(
                database.raw(
                    `truncate table public.${tables.v2ReleaseJobs}, public.${tables.v2ReleaseJobTransitionGuards}`
                ),
                "release jobs cannot be truncated"
            );
        });
    });

    it("M3-03 binds outbox payloads and makes acknowledgement immutable", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const now = new Date();
            const application = v2ApplicationRow();
            const releaseId = "10000000-0000-4000-8000-000000000030";
            await database(tables.v2Applications).insert(application);
            await database(tables.v2Releases).insert(
                v2ReadyReleaseRow(releaseId)
            );
            await database(tables.v2Idempotency).insert(
                v2IdempotencyRow("60000000-0000-4000-8000-000000000030", now)
            );
            await database(tables.v2Idempotency).insert({
                ...v2IdempotencyRow(
                    "60000000-0000-4000-8000-000000000031",
                    now
                ),
                scope: "application.unpublish",
            });
            await database(tables.v2Idempotency).insert({
                ...v2IdempotencyRow(
                    "60000000-0000-4000-8000-000000000033",
                    now
                ),
                idempotency_key: "idempotency-key-0033",
                scope: "release.restore",
            });
            await database(tables.v2Applications)
                .where({ id: application.id })
                .update({
                    desired_current_release_id: releaseId,
                    desired_generation: 1,
                });
            const outboxId = "80000000-0000-4000-8000-000000000030";
            await expectDatabaseError(
                database(tables.v2PublicationOutbox).insert({
                    ...v2OutboxRow(
                        "80000000-0000-4000-8000-000000000026",
                        application,
                        releaseId,
                        now
                    ),
                    state: "ACKNOWLEDGED",
                    attempt_count: 1,
                    lease_version: 1,
                    next_attempt_at: null,
                    acknowledged_at: now,
                    projection_digest: "c".repeat(64),
                }),
                "outbox row must start pending and unclaimed"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox).insert({
                    ...v2OutboxRow(
                        "80000000-0000-4000-8000-000000000023",
                        application,
                        releaseId,
                        now
                    ),
                    operation: "RESTORE",
                    idempotency_id: "60000000-0000-4000-8000-000000000033",
                }),
                "outbox release payload must match immutable READY release"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox).insert({
                    ...v2OutboxRow(
                        "80000000-0000-4000-8000-000000000029",
                        application,
                        releaseId,
                        now
                    ),
                    manifest_digest: "e".repeat(64),
                }),
                "outbox release payload must match immutable READY release"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox).insert({
                    ...v2OutboxRow(
                        "80000000-0000-4000-8000-000000000028",
                        application,
                        releaseId,
                        now
                    ),
                    operation: "UNPUBLISH",
                }),
                "outbox idempotency scope or state does not match operation"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox).insert({
                    ...v2OutboxRow(
                        "80000000-0000-4000-8000-000000000025",
                        application,
                        releaseId,
                        now
                    ),
                    idempotency_id: "60000000-0000-4000-8000-000000000031",
                }),
                "outbox idempotency scope or state does not match operation"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox).insert({
                    ...v2OutboxRow(
                        "80000000-0000-4000-8000-000000000024",
                        application,
                        releaseId,
                        now
                    ),
                    operation: "UNPUBLISH",
                    idempotency_id: "60000000-0000-4000-8000-000000000031",
                }),
                "v2_publication_outbox_payload_check"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox).insert({
                    ...v2OutboxRow(
                        "80000000-0000-4000-8000-000000000027",
                        application,
                        releaseId,
                        now
                    ),
                    idempotency_id: "60000000-0000-4000-8000-000000000099",
                }),
                "outbox idempotency identity not found"
            );
            await database(tables.v2PublicationOutbox).insert(
                v2OutboxRow(outboxId, application, releaseId, now)
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox).insert({
                    ...v2OutboxRow(
                        "80000000-0000-4000-8000-000000000031",
                        application,
                        releaseId,
                        now
                    ),
                    generation: 2,
                }),
                "outbox payload must match desired application generation"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .update({
                        state: "FAILED",
                        next_attempt_at: null,
                        last_error_code: "DIRECT_FAILURE",
                    }),
                "illegal publication outbox state transition"
            );
            await database(tables.v2PublicationOutbox)
                .where({ id: outboxId })
                .update({
                    next_attempt_at: new Date(now.getTime() + 3_600_000),
                });
            await expectDatabaseError(
                database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .update({
                        state: "LEASED",
                        lease_owner: "worker-early",
                        lease_expires_at: new Date(now.getTime() + 7_200_000),
                        attempt_count: 1,
                        lease_version: 1,
                        next_attempt_at: null,
                    }),
                "publication outbox row is not due for claim"
            );
            await database(tables.v2PublicationOutbox)
                .where({ id: outboxId })
                .update({ next_attempt_at: now });
            await expectDatabaseError(
                database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .update({
                        state: "LEASED",
                        lease_owner: "worker-unfenced",
                        lease_expires_at: new Date(now.getTime() + 3_600_000),
                        attempt_count: 1,
                        next_attempt_at: null,
                        updated_at: now,
                    }),
                "outbox claim must advance attempt and lease version"
            );
            await database(tables.v2PublicationOutbox)
                .where({ id: outboxId })
                .update({
                    state: "LEASED",
                    lease_owner: "worker-a",
                    lease_expires_at: new Date(now.getTime() + 3_600_000),
                    attempt_count: 1,
                    lease_version: 1,
                    next_attempt_at: null,
                    updated_at: now,
                });
            await expectDatabaseError(
                database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .update({
                        state: "PENDING",
                        lease_owner: null,
                        lease_expires_at: null,
                        next_attempt_at: now,
                        last_error_code: "EARLY_RETRY",
                    }),
                "leased outbox transition must use a guarded function"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .update({
                        lease_owner: "worker-b",
                        lease_expires_at: new Date(now.getTime() + 7_200_000),
                        attempt_count: 2,
                        lease_version: 2,
                    }),
                "live outbox lease cannot be reclaimed"
            );
            const acknowledgementTime = new Date(now.getTime() + 1_000);
            await expectDatabaseError(
                database(tables.v2Applications)
                    .where({ id: application.id })
                    .update({
                        served_current_release_id: releaseId,
                        served_generation: 1,
                    }),
                "served projection must use v2_acknowledge_publication"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .update({
                        state: "ACKNOWLEDGED",
                        lease_owner: null,
                        lease_expires_at: null,
                        next_attempt_at: null,
                        acknowledged_at: acknowledgementTime,
                        projection_digest: "c".repeat(64),
                        updated_at: acknowledgementTime,
                    }),
                "leased outbox transition must use a guarded function"
            );
            const beforeAcknowledgement = (
                await database.raw("select clock_timestamp() as now")
            ).rows[0].now as Date;
            const acknowledgement = await database.raw(
                "select public.v2_acknowledge_publication(?, ?, ?, ?) as label",
                [outboxId, "worker-a", 1, "c".repeat(64)]
            );
            const afterAcknowledgement = (
                await database.raw("select clock_timestamp() as now")
            ).rows[0].now as Date;
            const acknowledgedAt = (
                await database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .first("acknowledged_at")
            ).acknowledged_at as Date;
            expect(acknowledgedAt.getTime()).to.be.at.least(
                beforeAcknowledgement.getTime()
            );
            expect(acknowledgedAt.getTime()).to.be.at.most(
                afterAcknowledgement.getTime()
            );
            expect(acknowledgement.rows[0].label).to.match(
                /^\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}$/
            );
            expect(
                await database(tables.v2Applications)
                    .where({ id: application.id })
                    .first("served_current_release_id", "served_generation")
            ).to.deep.equal({
                served_current_release_id: releaseId,
                served_generation: "1",
            });
            await database(tables.v2Idempotency).insert({
                ...v2IdempotencyRow(
                    "60000000-0000-4000-8000-000000000034",
                    now
                ),
                idempotency_key: "idempotency-key-0034",
            });
            await expectDatabaseError(
                database(tables.v2PublicationOutbox).insert({
                    ...v2OutboxRow(
                        "80000000-0000-4000-8000-000000000034",
                        application,
                        releaseId,
                        now
                    ),
                    idempotency_id: "60000000-0000-4000-8000-000000000034",
                }),
                "outbox release payload must match immutable READY release"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .update({ projection_digest: "d".repeat(64) }),
                "terminal outbox row is immutable"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .delete(),
                "publication outbox rows cannot be deleted"
            );

            await database(tables.v2Applications)
                .where({ id: application.id })
                .update({
                    desired_current_release_id: null,
                    desired_generation: 2,
                });
            await database.raw(
                "create temporary table v2_applications (id uuid primary key)"
            );
            const tombstoneId = "80000000-0000-4000-8000-000000000032";
            const tombstoneIdempotencyId =
                "60000000-0000-4000-8000-000000000032";
            await database(tables.v2Idempotency).insert({
                ...v2IdempotencyRow(tombstoneIdempotencyId, now),
                idempotency_key: "idempotency-key-0032",
                scope: "application.unpublish",
            });
            const tombstoneCreatedAt = new Date(now.getTime() - 7_200_000);
            await database(tables.v2PublicationOutbox).insert({
                id: tombstoneId,
                application_id: application.id,
                routing_id: application.routing_id,
                generation: 2,
                operation: "UNPUBLISH",
                idempotency_id: tombstoneIdempotencyId,
                payload_kind: "TOMBSTONE",
                max_attempts: 3,
                created_at: tombstoneCreatedAt,
                updated_at: tombstoneCreatedAt,
                next_attempt_at: tombstoneCreatedAt,
            });
            await database.raw("drop table pg_temp.v2_applications");
            await database(tables.v2PublicationOutbox)
                .where({ id: tombstoneId })
                .update({
                    state: "LEASED",
                    lease_owner: "worker-old",
                    lease_expires_at: new Date(now.getTime() - 3_600_000),
                    attempt_count: 1,
                    lease_version: 1,
                    next_attempt_at: null,
                    updated_at: tombstoneCreatedAt,
                });
            await database(tables.v2PublicationOutbox)
                .where({ id: tombstoneId, state: "LEASED" })
                .where("lease_expires_at", "<", new Date())
                .update({
                    lease_owner: "worker-tombstone",
                    lease_expires_at: new Date(now.getTime() + 3_600_000),
                    attempt_count: 2,
                    lease_version: 2,
                    updated_at: now,
                });
            await expectDatabaseError(
                database.raw(
                    "select public.v2_acknowledge_publication(?, ?, ?, ?)",
                    [tombstoneId, "worker-old", 1, "d".repeat(64)]
                ),
                "active outbox lease fencing does not match"
            );
            await expectDatabaseError(
                database.raw(
                    "select public.v2_finish_publication_attempt(?, ?, ?, ?, ?, ?)",
                    [
                        tombstoneId,
                        "worker-tombstone",
                        2,
                        null,
                        "NULL_OUTCOME",
                        null,
                    ]
                ),
                "publication attempt arguments are invalid"
            );
            await database.raw(
                "select public.v2_finish_publication_attempt(?, ?, ?, ?, ?, ?)",
                [
                    tombstoneId,
                    "worker-tombstone",
                    2,
                    "RETRY",
                    "RETRYABLE_FAILURE",
                    null,
                ]
            );
            await database(tables.v2PublicationOutbox)
                .where({ id: tombstoneId, state: "PENDING" })
                .update({
                    state: "LEASED",
                    lease_owner: "worker-final",
                    lease_expires_at: new Date(Date.now() + 3_600_000),
                    attempt_count: 3,
                    lease_version: 3,
                    next_attempt_at: null,
                    last_error_code: null,
                    updated_at: new Date(),
                });
            await expectDatabaseError(
                database.raw(
                    "select public.v2_finish_publication_attempt(?, ?, ?, ?, ?, ?)",
                    [
                        tombstoneId,
                        "worker-final",
                        3,
                        "RETRY",
                        "RETRYABLE_FAILURE",
                        null,
                    ]
                ),
                "final publication attempt cannot be retried"
            );
            await database(tables.v2Applications)
                .where({ id: application.id })
                .update({ desired_generation: 3 });
            await expectDatabaseError(
                database.raw(
                    "select public.v2_acknowledge_publication(?, ?, ?, ?)",
                    [tombstoneId, "worker-final", 3, "d".repeat(64)]
                ),
                "outbox generation is no longer desired"
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox)
                    .where({ id: tombstoneId })
                    .update({
                        state: "FAILED",
                        lease_owner: null,
                        lease_expires_at: null,
                        next_attempt_at: null,
                        last_error_code: "RETRY_EXHAUSTED",
                    }),
                "leased outbox transition must use a guarded function"
            );
            await database.raw(
                "select public.v2_finish_publication_attempt(?, ?, ?, ?, ?, ?)",
                [
                    tombstoneId,
                    "worker-final",
                    3,
                    "FAILED",
                    "RETRY_EXHAUSTED",
                    null,
                ]
            );
            await expectDatabaseError(
                database(tables.v2PublicationOutbox)
                    .where({ id: tombstoneId })
                    .update({ last_error_code: "ALTERED" }),
                "terminal outbox row is immutable"
            );
            await expectDatabaseError(
                database.raw(
                    `truncate table public.${tables.v2PublicationOutbox}, public.${tables.v2OutboxTransitionGuards}`
                ),
                "publication outbox cannot be truncated"
            );
        });
    });

    it("M3-03 enforces worker transition privilege boundaries", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const now = new Date();
            const application = v2ApplicationRow();
            const releaseId = "10000000-0000-4000-8000-000000000036";
            const jobId = "70000000-0000-4000-8000-000000000036";
            const outboxId = "80000000-0000-4000-8000-000000000036";
            const idempotencyId = "60000000-0000-4000-8000-000000000036";
            const role = `m303_worker_${randomBytes(6).toString("hex")}`;
            await database(tables.v2Applications).insert(application);
            await database(tables.v2Releases).insert(
                v2ReadyReleaseRow(releaseId)
            );
            await database(tables.v2Idempotency).insert({
                ...v2IdempotencyRow(idempotencyId, now),
                idempotency_key: "idempotency-key-0036",
            });
            await database(tables.v2Applications)
                .where({ id: application.id })
                .update({
                    desired_current_release_id: releaseId,
                    desired_generation: 1,
                });
            await database(tables.v2ReleaseJobs).insert(
                v2ReleaseJobRow(jobId, releaseId, now)
            );
            await database(tables.v2ReleaseJobs)
                .where({ id: jobId })
                .update({
                    state: "LEASED",
                    lease_owner: "worker-role",
                    lease_expires_at: new Date(now.getTime() + 3_600_000),
                    attempt_count: 1,
                    lease_version: 1,
                    next_attempt_at: null,
                });
            await database(tables.v2PublicationOutbox).insert({
                ...v2OutboxRow(outboxId, application, releaseId, now),
                idempotency_id: idempotencyId,
            });
            await database(tables.v2PublicationOutbox)
                .where({ id: outboxId })
                .update({
                    state: "LEASED",
                    lease_owner: "worker-role",
                    lease_expires_at: new Date(now.getTime() + 3_600_000),
                    attempt_count: 1,
                    lease_version: 1,
                    next_attempt_at: null,
                });

            await database.raw("create role ?? nologin", [role]);
            try {
                await database.raw("grant usage on schema public to ??", [
                    role,
                ]);
                await database.raw(
                    `grant select, update on public.${tables.v2ReleaseJobs}, public.${tables.v2PublicationOutbox} to ??`,
                    [role]
                );
                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction.raw(
                            `select * from public.${tables.v2ReleaseJobTransitionGuards}`
                        );
                    }),
                    `permission denied for table ${tables.v2ReleaseJobTransitionGuards}`
                );
                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction(tables.v2ReleaseJobs)
                            .where({ id: jobId })
                            .update({
                                state: "SUCCEEDED",
                                lease_owner: null,
                                lease_expires_at: null,
                                next_attempt_at: null,
                                completed_at: new Date(),
                            });
                    }),
                    "leased release job transition must use v2_finish_release_job_attempt"
                );
                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction(tables.v2PublicationOutbox)
                            .where({ id: outboxId })
                            .update({
                                state: "FAILED",
                                lease_owner: null,
                                lease_expires_at: null,
                                next_attempt_at: null,
                                last_error_code: "DIRECT_FAILURE",
                            });
                    }),
                    "leased outbox transition must use a guarded function"
                );
                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction.raw(
                            "select public.v2_finish_release_job_attempt(?, ?, ?, ?, ?, ?, ?)",
                            [
                                jobId,
                                "worker-role",
                                1,
                                "SUCCEEDED",
                                null,
                                null,
                                null,
                            ]
                        );
                    }),
                    "permission denied for function v2_finish_release_job_attempt"
                );
                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction.raw(
                            "select public.v2_finish_publication_attempt(?, ?, ?, ?, ?, ?)",
                            [
                                outboxId,
                                "worker-role",
                                1,
                                "FAILED",
                                "WORKER_FAILURE",
                                null,
                            ]
                        );
                    }),
                    "permission denied for function v2_finish_publication_attempt"
                );

                await database.raw(
                    `grant execute on function public.v2_finish_release_job_attempt(uuid, text, bigint, text, text, text, timestamptz) to ??`,
                    [role]
                );
                await database.raw(
                    `grant execute on function public.v2_finish_publication_attempt(uuid, text, bigint, text, text, timestamptz) to ??`,
                    [role]
                );
                await database.transaction(async (transaction) => {
                    await transaction.raw("set local role ??", [role]);
                    await transaction.raw(
                        "select public.v2_finish_release_job_attempt(?, ?, ?, ?, ?, ?, ?)",
                        [jobId, "worker-role", 1, "SUCCEEDED", null, null, null]
                    );
                    await transaction.raw(
                        "select public.v2_finish_publication_attempt(?, ?, ?, ?, ?, ?)",
                        [
                            outboxId,
                            "worker-role",
                            1,
                            "FAILED",
                            "WORKER_FAILURE",
                            null,
                        ]
                    );
                });
            } finally {
                await database.raw("drop owned by ??", [role]);
                await database.raw("drop role ??", [role]);
            }
            expect(
                await database(tables.v2ReleaseJobs)
                    .where({ id: jobId })
                    .first("state")
            ).to.deep.equal({ state: "SUCCEEDED" });
            expect(
                await database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .first("state")
            ).to.deep.equal({ state: "FAILED" });
        });
    });

    it("M3-03 retains copied outbox identity after idempotency expiry cleanup", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const now = new Date();
            const application = v2ApplicationRow();
            const releaseId = "10000000-0000-4000-8000-000000000035";
            const outboxId = "80000000-0000-4000-8000-000000000035";
            const idempotencyId = "60000000-0000-4000-8000-000000000035";
            await database(tables.v2Applications).insert(application);
            await database(tables.v2Releases).insert(
                v2ReadyReleaseRow(releaseId)
            );
            await database(tables.v2Idempotency).insert({
                ...v2IdempotencyRow(idempotencyId, now),
                idempotency_key: "idempotency-key-0035",
                expires_at: new Date(now.getTime() + 1_500),
            });
            await database(tables.v2Applications)
                .where({ id: application.id })
                .update({
                    desired_current_release_id: releaseId,
                    desired_generation: 1,
                });
            await database(tables.v2PublicationOutbox).insert({
                ...v2OutboxRow(outboxId, application, releaseId, now),
                idempotency_id: idempotencyId,
            });

            await new Promise((resolve) => setTimeout(resolve, 1_600));
            await database(tables.v2Idempotency)
                .where({ id: idempotencyId })
                .delete();
            expect(
                await database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .first("idempotency_id")
            ).to.deep.equal({ idempotency_id: idempotencyId });
        });
    });

    it("M3-03 enforces the acknowledgement privilege boundary", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            const now = new Date();
            const application = v2ApplicationRow();
            const releaseId = "10000000-0000-4000-8000-000000000040";
            const outboxId = "80000000-0000-4000-8000-000000000040";
            const idempotencyId = "60000000-0000-4000-8000-000000000040";
            const role = `m303_${randomBytes(8).toString("hex")}`;
            await database(tables.v2Applications).insert(application);
            await database(tables.v2Releases).insert(
                v2ReadyReleaseRow(releaseId)
            );
            await database(tables.v2Idempotency).insert(
                v2IdempotencyRow(idempotencyId, now)
            );
            await database(tables.v2Applications)
                .where({ id: application.id })
                .update({
                    desired_current_release_id: releaseId,
                    desired_generation: 1,
                });
            await database(tables.v2PublicationOutbox).insert({
                ...v2OutboxRow(outboxId, application, releaseId, now),
                idempotency_id: idempotencyId,
            });
            await database(tables.v2PublicationOutbox)
                .where({ id: outboxId })
                .update({
                    state: "LEASED",
                    lease_owner: "worker-privilege",
                    lease_expires_at: new Date(now.getTime() + 3_600_000),
                    attempt_count: 1,
                    lease_version: 1,
                    next_attempt_at: null,
                    updated_at: now,
                });

            await database.raw("create role ?? nologin", [role]);
            try {
                await database.raw("grant usage on schema public to ??", [
                    role,
                ]);
                await database.raw(
                    `grant select, update on public.${tables.v2PublicationOutbox} to ??`,
                    [role]
                );
                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction.raw(
                            `select * from public.${tables.v2OutboxTransitionGuards}`
                        );
                    }),
                    `permission denied for table ${tables.v2OutboxTransitionGuards}`
                );
                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction.raw(
                            "select public.v2_acknowledge_publication(?, ?, ?, ?)",
                            [outboxId, "worker-privilege", 1, "e".repeat(64)]
                        );
                    }),
                    "permission denied for function v2_acknowledge_publication"
                );
                await expectDatabaseError(
                    database.transaction(async (transaction) => {
                        await transaction.raw("set local role ??", [role]);
                        await transaction(tables.v2PublicationOutbox)
                            .where({ id: outboxId })
                            .update({
                                state: "ACKNOWLEDGED",
                                lease_owner: null,
                                lease_expires_at: null,
                                next_attempt_at: null,
                                acknowledged_at: new Date(
                                    now.getTime() + 1_000
                                ),
                                projection_digest: "e".repeat(64),
                            });
                    }),
                    "leased outbox transition must use a guarded function"
                );

                await database.raw(
                    `grant execute on function public.v2_acknowledge_publication(uuid, text, bigint, text) to ??`,
                    [role]
                );
                await database.transaction(async (transaction) => {
                    await transaction.raw("set local role ??", [role]);
                    await transaction.raw(
                        "select public.v2_acknowledge_publication(?, ?, ?, ?)",
                        [outboxId, "worker-privilege", 1, "e".repeat(64)]
                    );
                });
            } finally {
                await database.raw("drop owned by ??", [role]);
                await database.raw("drop role ??", [role]);
            }
            expect(
                await database(tables.v2PublicationOutbox)
                    .where({ id: outboxId })
                    .first("state")
            ).to.deep.equal({ state: "ACKNOWLEDGED" });
        });
    });

    it("M3-03 uses operational expiry, claim, and generation indexes", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);
            await database.raw(`
                INSERT INTO public.${tables.v2Sessions}
                    (id, subject_id, issuer, claims, claims_version,
                     csrf_token_digest, created_at, last_seen_at,
                     idle_expires_at, absolute_expires_at)
                SELECT
                    ('50000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    'subject-' || lpad((i % 100)::text, 3, '0'),
                    'https://issuer.example.test', '{}'::jsonb, 1,
                    repeat('a', 64),
                    transaction_timestamp() - interval '1 hour',
                    transaction_timestamp() - interval '30 minutes',
                    transaction_timestamp() + (i + 1) * interval '1 minute',
                    transaction_timestamp() + interval '30 days'
                FROM generate_series(1, 5000) AS generated(i);

                INSERT INTO public.${tables.v2Idempotency}
                    (id, actor_id, scope, idempotency_key, request_digest,
                     created_at, expires_at)
                SELECT
                    ('60000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    'actor-' || lpad((i % 100)::text, 3, '0'),
                    'release.publish',
                    'idempotency-key-' || lpad(i::text, 8, '0'),
                    repeat('b', 64),
                    transaction_timestamp() - i * interval '1 second',
                    transaction_timestamp() + interval '1 day'
                FROM generate_series(1, 10000) AS generated(i);

                INSERT INTO public.${tables.v2Applications}
                    (id, name, routing_id, created_at, updated_at)
                SELECT
                    ('01000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    'operational-app-' || lpad(i::text, 4, '0'),
                    ('02000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    transaction_timestamp(), transaction_timestamp()
                FROM generate_series(1, 2000) AS generated(i);

                INSERT INTO public.${tables.v2Releases}
                    (id, application_id, state, default_path, manifest_digest,
                     finalized_at, created_at, updated_at)
                SELECT
                    ('03000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    ('01000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    'READY', 'index.html', repeat('c', 64),
                    transaction_timestamp(), transaction_timestamp(),
                    transaction_timestamp()
                FROM generate_series(1, 2000) AS generated(i);

                INSERT INTO public.${tables.v2ReleaseJobs}
                    (id, release_id, state, next_attempt_at,
                     created_at, updated_at)
                SELECT
                    ('70000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    ('03000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    'PENDING', transaction_timestamp() - i * interval '1 second',
                    transaction_timestamp(), transaction_timestamp()
                FROM generate_series(1, 2000) AS generated(i);

                UPDATE public.${tables.v2Applications} AS application
                   SET desired_current_release_id = release.id,
                       desired_generation = 1
                  FROM public.${tables.v2Releases} AS release
                 WHERE release.application_id = application.id;

                WITH numbered AS (
                    SELECT application.*,
                           row_number() OVER (ORDER BY application.id) AS i
                      FROM public.${tables.v2Applications} AS application
                )
                INSERT INTO public.${tables.v2PublicationOutbox}
                    (id, application_id, routing_id, release_id, generation,
                     operation, idempotency_id, payload_kind, manifest_digest,
                     object_prefix, state, next_attempt_at, created_at, updated_at)
                SELECT
                    ('80000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    id, routing_id, desired_current_release_id, 1,
                    'PUBLISH',
                    ('60000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                    'RELEASE', repeat('c', 64),
                    'v2/releases/' || id::text || '/' ||
                        desired_current_release_id::text,
                    'PENDING', transaction_timestamp() - i * interval '1 second',
                    transaction_timestamp(), transaction_timestamp()
                FROM numbered;

                UPDATE public.${tables.v2Sessions}
                   SET revoked_at = transaction_timestamp(),
                       revocation_reason = 'PLAN_CLEANUP'
                 WHERE id IN (
                    SELECT id FROM public.${tables.v2Sessions}
                    ORDER BY id LIMIT 500
                 );

                UPDATE public.${tables.v2ReleaseJobs}
                   SET state = 'LEASED',
                       lease_owner = 'plan-worker',
                       lease_expires_at = transaction_timestamp() + interval '1 hour',
                       attempt_count = 1,
                       lease_version = 1,
                       next_attempt_at = NULL
                 WHERE id IN (
                    SELECT id FROM public.${tables.v2ReleaseJobs}
                    ORDER BY id LIMIT 100
                 );

                UPDATE public.${tables.v2PublicationOutbox}
                   SET state = 'LEASED',
                       lease_owner = 'plan-worker',
                       lease_expires_at = transaction_timestamp() + interval '1 hour',
                       attempt_count = 1,
                       lease_version = 1,
                       next_attempt_at = NULL
                 WHERE id IN (
                    SELECT id FROM public.${tables.v2PublicationOutbox}
                    ORDER BY id LIMIT 100
                 );

                ANALYZE public.${tables.v2Sessions};
                ANALYZE public.${tables.v2Idempotency};
                ANALYZE public.${tables.v2ReleaseJobs};
                ANALYZE public.${tables.v2PublicationOutbox};
            `);

            expect(
                await explainText(
                    database,
                    `select id from public.${tables.v2Sessions}
                      where subject_id = 'subject-001'
                        and revoked_at is null
                      order by absolute_expires_at, id
                      limit 50`
                )
            ).to.include("v2_sessions_subject_active_idx");
            expect(
                await explainText(
                    database,
                    `select id from public.${tables.v2Sessions}
                      where revoked_at is null
                      order by idle_expires_at, absolute_expires_at, id
                      limit 50`
                )
            ).to.include("v2_sessions_active_expiry_idx");
            expect(
                await explainText(
                    database,
                    `select id from public.${tables.v2Sessions}
                      where revoked_at is not null
                      order by revoked_at, id
                      limit 50`
                )
            ).to.include("v2_sessions_revoked_cleanup_idx");
            expect(
                await explainText(
                    database,
                    `select id from public.${tables.v2Idempotency}
                      where actor_id = 'actor-001'
                        and scope = 'release.publish'
                      order by created_at desc, id desc
                      limit 50`
                )
            ).to.include("v2_idempotency_actor_scope_created_idx");
            expect(
                await explainText(
                    database,
                    `select id from public.${tables.v2Idempotency}
                      order by expires_at, id
                      limit 50`
                )
            ).to.include("v2_idempotency_expiry_idx");
            expect(
                await explainText(
                    database,
                    `select id from public.${tables.v2ReleaseJobs}
                      where state = 'PENDING'
                      order by next_attempt_at, created_at, id
                      limit 50`
                )
            ).to.include("v2_release_jobs_claim_idx");
            expect(
                await explainText(
                    database,
                    `select id from public.${tables.v2ReleaseJobs}
                      where state = 'LEASED'
                      order by lease_expires_at, id
                      limit 50`
                )
            ).to.include("v2_release_jobs_lease_expiry_idx");
            expect(
                await explainText(
                    database,
                    `select id from public.${tables.v2PublicationOutbox}
                      where state = 'PENDING'
                      order by next_attempt_at, created_at, id
                      limit 50`
                )
            ).to.include("v2_publication_outbox_claim_idx");
            expect(
                await explainText(
                    database,
                    `select id from public.${tables.v2PublicationOutbox}
                      where state = 'LEASED'
                      order by lease_expires_at, id
                      limit 50`
                )
            ).to.include("v2_publication_outbox_lease_expiry_idx");
            expect(
                await explainText(
                    database,
                    `select id from public.${tables.v2PublicationOutbox}
                      order by application_id, generation desc, id desc
                      limit 50`
                )
            ).to.include("v2_publication_outbox_application_generation_idx");
        });
    });

    it("rolls back a failed transaction and reuses the connection", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await database.migrate.latest(productionMigrationConfig);

            let transactionError: unknown;
            try {
                await database.transaction(async (transaction) => {
                    await transaction(tables.apps).insert(appRow());
                    await transaction(tables.apps).insert(appRow());
                });
            } catch (error) {
                transactionError = error;
            }

            expect(transactionError).to.be.instanceOf(Error);
            expect(
                await database(tables.apps).count("id as count").first()
            ).to.deep.equal({ count: "0" });
            expect(
                (await database.raw("select 1 as value")).rows[0]
            ).to.deep.equal({
                value: 1,
            });
        });
    });

    it("bounds pool exhaustion and recovers after the held connection is released", async () => {
        await withDisposableDatabase(admin, async (_database, url) => {
            const bounded = createPostgresKnex(url, {
                ...defaultPostgresClientOptions,
                poolMax: 1,
                acquireConnectionTimeoutMillis: 150,
            });
            let connection: unknown;
            try {
                connection = await bounded.client.acquireConnection();
                const startedAt = Date.now();
                let exhaustionError: unknown;
                try {
                    await bounded.raw("select 1");
                } catch (error) {
                    exhaustionError = error;
                }
                const elapsedMillis = Date.now() - startedAt;

                expect(exhaustionError).to.be.instanceOf(Error);
                expect((exhaustionError as Error).name).to.equal(
                    "KnexTimeoutError"
                );
                expect(elapsedMillis).to.be.greaterThan(100);
                expect(elapsedMillis).to.be.lessThan(2_000);

                await bounded.client.releaseConnection(connection);
                connection = undefined;
                expect(
                    (await bounded.raw("select 1 as value")).rows[0]
                ).to.deep.equal({ value: 1 });
            } finally {
                try {
                    if (connection !== undefined) {
                        await bounded.client.releaseConnection(connection);
                    }
                } finally {
                    await bounded.destroy();
                }
            }
        });
    });

    it("enforces the configured PostgreSQL connection timeout", async () => {
        const sockets = new Set<Socket>();
        const server = createServer((socket) => {
            sockets.add(socket);
            socket.on("close", () => sockets.delete(socket));
        });
        await new Promise<void>((resolve) =>
            server.listen(0, "127.0.0.1", resolve)
        );
        const address = server.address();
        if (address === null || typeof address === "string") {
            throw new Error("Test TCP server did not expose a port");
        }
        const database = createPostgresKnex(
            `postgres://postgres:test@127.0.0.1:${address.port}/postgres`,
            {
                ...defaultPostgresClientOptions,
                connectionTimeoutMillis: 250,
                acquireConnectionTimeoutMillis: 1_000,
            }
        );
        const startedAt = Date.now();
        let connectionError: unknown;
        try {
            await database.raw("select 1");
        } catch (error) {
            connectionError = error;
        } finally {
            try {
                await database.destroy();
            } finally {
                for (const socket of sockets) socket.destroy();
                await new Promise<void>((resolve, reject) =>
                    server.close((error) =>
                        error === undefined ? resolve() : reject(error)
                    )
                );
            }
        }
        const elapsedMillis = Date.now() - startedAt;
        expect(connectionError).to.be.instanceOf(Error);
        expect(elapsedMillis).to.be.greaterThan(175);
        expect(elapsedMillis).to.be.lessThan(2_000);
    });

    it("bounds unreachable setup failures as StorageSetupError", async () => {
        const module = new PgS3Storages({
            postgresUrl:
                "postgres://postgres:not-a-secret@127.0.0.1:1/postgres",
            s3Config: testS3Config(),
        });
        const startedAt = Date.now();
        let setupError: unknown;
        try {
            await module.setup();
        } catch (error) {
            setupError = error;
        } finally {
            await Promise.all([module.destroy(), module.destroy()]);
        }

        expect(setupError).to.be.instanceOf(StorageSetupError);
        expect((setupError as Error).message).to.equal(
            "Error running sql migration"
        );
        expect(Date.now() - startedAt).to.be.lessThan(15_000);
        expect(errorText(setupError)).not.to.include("not-a-secret");
    });

    it("attempts every resource cleanup once and caches destroy failures", async () => {
        const module = new PgS3Storages({
            postgresUrl,
            s3Config: testS3Config(),
        });
        const originalKnex: Knex = (module as any).knex;
        const originalS3Client = (module as any).s3Client;
        await originalKnex.destroy();
        originalS3Client.destroy();

        let s3DestroyCount = 0;
        let postgresDestroyCount = 0;
        (module as any).s3Client = {
            destroy: () => {
                s3DestroyCount += 1;
                throw new Error("controlled S3 destroy failure");
            },
        };
        (module as any).knex = {
            destroy: async () => {
                postgresDestroyCount += 1;
            },
        };

        const firstDestroy = module.destroy();
        const secondDestroy = module.destroy();
        expect(secondDestroy).to.equal(firstDestroy);
        let destroyError: unknown;
        try {
            await Promise.all([firstDestroy, secondDestroy]);
        } catch (error) {
            destroyError = error;
        }
        expect((destroyError as Error).message).to.equal(
            "controlled S3 destroy failure"
        );
        expect(s3DestroyCount).to.equal(1);
        expect(postgresDestroyCount).to.equal(1);
    });

    it("inspects non-enumerable nested error details for credential checks", () => {
        const nested = new Error("outer");
        Object.defineProperty(nested, "originalError", {
            value: new Error("hidden-test-secret"),
            enumerable: false,
        });
        expect(errorText(nested)).to.include("hidden-test-secret");
    });

    it("reports bad PostgreSQL credentials unhealthy within the configured bound", async () => {
        const badUrl = new URL(postgresUrl);
        badUrl.password = "definitely-wrong";
        const module = new PgS3Storages({
            postgresUrl: badUrl.toString(),
            s3Config: testS3Config(),
        });
        const startedAt = Date.now();
        let setupError: unknown;
        let health: IHealthCheckResult = { isHealthy: true, details: {} };
        try {
            try {
                await module.setup();
            } catch (error) {
                setupError = error;
            }
            expect(setupError).to.be.instanceOf(StorageSetupError);
            health = await module.getStorages().checkHealth();
        } finally {
            await module.destroy();
        }

        expect(Date.now() - startedAt).to.be.lessThan(15_000);
        expect(health.isHealthy).to.equal(false);
        expect(health.details.postgres.message).to.equal(
            "Unable to run query 'select 1'"
        );
        expect(errorText(setupError)).not.to.include("definitely-wrong");
        expect(errorText(health.details.postgres)).not.to.include(
            "definitely-wrong"
        );
    });

    it("rolls back a failed migration, releases its lock, and retries cleanly", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await withTemporaryDirectory(
                "staticdeploy-pg-",
                async (directory) => {
                    const sentinel = join(directory, "allow-retry");
                    const migrationPath = join(directory, "00_atomic.js");
                    await writeFile(
                        migrationPath,
                        `const fs = require("node:fs");\n` +
                            `exports.up = async (knex) => {\n` +
                            `  await knex.schema.createTable("test_atomic", (table) => table.string("id").primary());\n` +
                            `  await knex("test_atomic").insert({ id: "partial" });\n` +
                            `  if (!fs.existsSync(${JSON.stringify(sentinel)})) throw new Error("controlled migration failure");\n` +
                            `};\n` +
                            `exports.down = (knex) => knex.schema.dropTable("test_atomic");\n`
                    );
                    const config: Knex.MigratorConfig = {
                        directory,
                        loadExtensions: [".js"],
                    };

                    let migrationError: unknown;
                    try {
                        await database.migrate.latest(config);
                    } catch (error) {
                        migrationError = error;
                    }
                    expect(migrationError).to.be.instanceOf(Error);
                    expect(
                        await database.schema.hasTable("test_atomic")
                    ).to.equal(false);
                    expect(await migrationNames(database)).to.deep.equal([]);
                    expect(
                        (await database("knex_migrations_lock").first())
                            .is_locked
                    ).to.equal(0);

                    await writeFile(sentinel, "retry allowed\n");
                    const retry = await database.migrate.latest(config);
                    expect(retry[1]).to.deep.equal(["00_atomic.js"]);
                    expect(
                        await database("test_atomic").select("id")
                    ).to.deep.equal([{ id: "partial" }]);
                }
            );
        });
    });

    it("rehearses down and reapply for a test-only reversible additive migration", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await withTemporaryDirectory(
                "staticdeploy-pg-",
                async (directory) => {
                    await writeFile(
                        join(directory, "00_reversible.js"),
                        `exports.up = (knex) => knex.schema.createTable("test_additive", (table) => table.string("id").primary());\n` +
                            `exports.down = (knex) => knex.schema.dropTable("test_additive");\n`
                    );
                    const config: Knex.MigratorConfig = {
                        directory,
                        loadExtensions: [".js"],
                    };

                    await database.migrate.latest(config);
                    await database("test_additive").insert({ id: "rehearsal" });
                    expect(
                        await database.schema.hasTable("test_additive")
                    ).to.equal(true);

                    const down = await database.migrate.down(config);
                    expect(down[1]).to.deep.equal(["00_reversible.js"]);
                    expect(
                        await database.schema.hasTable("test_additive")
                    ).to.equal(false);

                    const reapply = await database.migrate.latest(config);
                    expect(reapply[1]).to.deep.equal(["00_reversible.js"]);
                    expect(
                        await database.schema.hasTable("test_additive")
                    ).to.equal(true);
                }
            );
        });
    });
});

async function withTemporaryDirectory(
    prefix: string,
    callback: (directory: string) => Promise<void>
): Promise<void> {
    const directory = await mkdtemp(join(tmpdir(), prefix));
    let operationError: unknown;
    try {
        await callback(directory);
    } catch (error) {
        operationError = error;
    }

    let cleanupError: unknown;
    try {
        await rm(directory, { recursive: true, force: true });
    } catch (error) {
        cleanupError = error;
    }
    if (operationError !== undefined) throw operationError;
    if (cleanupError !== undefined) throw cleanupError;
}

async function withDisposableDatabase(
    admin: Knex,
    callback: (database: Knex, url: string) => Promise<void>
): Promise<void> {
    const databaseName = `staticdeploy_m205_${randomBytes(8).toString("hex")}`;
    const url = new URL(postgresUrl);
    url.pathname = `/${databaseName}`;
    await admin.raw(`CREATE DATABASE "${databaseName}"`);
    const database = createPostgresKnex(url.toString());
    let operationError: unknown;
    try {
        await callback(database, url.toString());
    } catch (error) {
        operationError = error;
    }

    let cleanupError: unknown;
    for (const cleanup of [
        () => database.destroy(),
        () =>
            admin.raw(
                "select pg_terminate_backend(pid) from pg_stat_activity where datname = ? and pid <> pg_backend_pid()",
                [databaseName]
            ),
        () => admin.raw(`DROP DATABASE IF EXISTS "${databaseName}"`),
    ]) {
        try {
            await cleanup();
        } catch (error) {
            if (cleanupError === undefined) cleanupError = error;
        }
    }
    if (operationError !== undefined) throw operationError;
    if (cleanupError !== undefined) throw cleanupError;
}

async function prepareProductionMigrationConfig(): Promise<{
    config: Knex.MigratorConfig;
    fallbackDirectory?: string;
}> {
    const compiledDirectory = join(__dirname, "../lib/migrations");
    try {
        await access(join(compiledDirectory, "00.js"));
        return {
            config: {
                directory: compiledDirectory,
                loadExtensions: [".js"],
            },
        };
    } catch {
        // A clean standalone unit run intentionally does not emit workspace
        // builds. Preserve production .js migration names with temporary
        // wrappers; exact CI runs after compile and therefore exercise lib/.
        const fallbackDirectory = await mkdtemp(
            join(tmpdir(), "staticdeploy-migration-wrappers-")
        );
        for (const name of ["00", "01", "02", "03", "04"]) {
            const sourcePath = join(__dirname, `../src/migrations/${name}.ts`);
            await writeFile(
                join(fallbackDirectory, `${name}.js`),
                `module.exports = require(${JSON.stringify(sourcePath)});\n`
            );
        }
        return {
            config: {
                directory: fallbackDirectory,
                loadExtensions: [".js"],
            },
            fallbackDirectory,
        };
    }
}

async function installLegacyFixture(
    database: Knex,
    fixtureName: keyof typeof legacyFixtures
): Promise<void> {
    const fixture = legacyFixtures[fixtureName];
    const sql = await readFile(
        join(__dirname, "fixtures", fixture.file),
        "utf8"
    );
    const actualSha256 = createHash("sha256").update(sql).digest("hex");
    expect(actualSha256).to.equal(fixture.sha256);
    await database.raw(sql);
}

function appRow() {
    return {
        id: "app-1",
        name: "application-one",
        defaultConfiguration: JSON.stringify({ retained: ["value", 1] }),
        createdAt: fixtureDate(),
        updatedAt: fixtureDate(),
    };
}

function fixtureDate(): Date {
    return new Date("2021-11-24T23:19:33.000Z");
}

async function legacySnapshot(database: Knex): Promise<LegacySnapshot> {
    const rows: Record<string, unknown[]> = {};
    for (const table of [
        tables.apps,
        tables.bundles,
        tables.entrypoints,
        tables.operationLogs,
        tables.groups,
        tables.users,
        tables.usersAndGroups,
    ]) {
        rows[table] = await database(table)
            .select("*")
            .orderBy(Object.keys(await database(table).columnInfo())[0]);
    }
    const foreignKeys = (
        await database.raw(
            `select conname as name,
                    conrelid::regclass::text as table_name,
                    pg_get_constraintdef(oid) as definition
               from pg_constraint
              where contype = 'f'
                and connamespace = 'public'::regnamespace
                and conrelid::regclass::text in ('entrypoints', 'users_groups')
              order by conrelid::regclass::text, conname`
        )
    ).rows;
    const migrationHistory = await database("knex_migrations")
        .select("id", "name", "batch", "migration_time")
        .orderBy("id");
    const migrationLock = await database("knex_migrations_lock")
        .select("index", "is_locked")
        .orderBy("index");
    return {
        rows,
        foreignKeys,
        migrationHistory,
        migrationLock,
        hash: createHash("sha256")
            .update(
                JSON.stringify({
                    rows,
                    foreignKeys,
                    migrationHistory,
                    migrationLock,
                })
            )
            .digest("hex"),
    };
}

async function applicationTables(database: Knex): Promise<string[]> {
    const rows = await database("information_schema.tables")
        .select("table_name")
        .where({ table_schema: "public", table_type: "BASE TABLE" })
        .whereNot("table_name", "like", "knex_migrations%")
        .orderBy("table_name");
    return rows.map((row: { table_name: string }) => row.table_name);
}

async function migrationNames(database: Knex): Promise<string[]> {
    if (!(await database.schema.hasTable("knex_migrations"))) {
        return [];
    }
    const rows = await database("knex_migrations").select("name").orderBy("id");
    return rows.map((row) => row.name);
}

function v2TableNames(): string[] {
    return [
        tables.v2Applications,
        tables.v2AuditEvents,
        tables.v2Bindings,
        tables.v2PublicationGuards,
        tables.v2Releases,
        tables.v2UploadFiles,
    ];
}

function v2OperationalTableNames(): string[] {
    return [
        tables.v2Idempotency,
        tables.v2OutboxTransitionGuards,
        tables.v2PublicationOutbox,
        tables.v2ReleaseJobTransitionGuards,
        tables.v2ReleaseJobs,
        tables.v2Sessions,
    ];
}

function v2ApplicationRow() {
    return {
        id: "00000000-0000-4000-8000-000000000001",
        name: "application-v2-one",
        description: "Schema contract fixture",
        tags: JSON.stringify(["fixture"]),
        owner_metadata: JSON.stringify({ source: "test" }),
        routing_id: "00000000-0000-4000-8000-000000000002",
        created_at: fixtureDate(),
        updated_at: fixtureDate(),
    };
}

function v2ReadyReleaseRow(id: string) {
    return {
        id,
        application_id: v2ApplicationRow().id,
        state: "READY",
        default_path: "nested/app.html",
        manifest_digest: "b".repeat(64),
        finalized_at: fixtureDate(),
        created_at: fixtureDate(),
        updated_at: fixtureDate(),
    };
}

function v2SessionRow(id: string, now: Date) {
    return {
        id,
        subject_id: "subject-1",
        issuer: "https://issuer.example.test",
        claims: JSON.stringify({ groups: ["viewer"] }),
        claims_version: 1,
        csrf_token_digest: "d".repeat(64),
        token_key_id: "session-key-1",
        token_nonce: Buffer.alloc(12, 0x11),
        encrypted_token_material: Buffer.alloc(32, 0x22),
        created_at: new Date(now.getTime() - 3_600_000),
        last_seen_at: new Date(now.getTime() - 1_800_000),
        idle_expires_at: new Date(now.getTime() + 3_600_000),
        absolute_expires_at: new Date(now.getTime() + 86_400_000),
    };
}

function v2IdempotencyRow(id: string, now: Date) {
    return {
        id,
        actor_id: "actor-1",
        scope: "release.publish",
        idempotency_key: "idempotency-key-0001",
        request_digest: "a".repeat(64),
        created_at: new Date(now.getTime() - 1_000),
        expires_at: new Date(now.getTime() + 86_400_000),
    };
}

function v2ReleaseJobRow(id: string, releaseId: string, now: Date) {
    return {
        id,
        release_id: releaseId,
        kind: "PROCESS_RELEASE",
        state: "PENDING",
        next_attempt_at: now,
        created_at: now,
        updated_at: now,
    };
}

function v2OutboxRow(
    id: string,
    application: ReturnType<typeof v2ApplicationRow>,
    releaseId: string,
    now: Date
) {
    return {
        id,
        application_id: application.id,
        routing_id: application.routing_id,
        release_id: releaseId,
        generation: 1,
        operation: "PUBLISH",
        idempotency_id: "60000000-0000-4000-8000-000000000030",
        payload_kind: "RELEASE",
        manifest_digest: "b".repeat(64),
        object_prefix: `v2/releases/${application.id}/${releaseId}`,
        state: "PENDING",
        next_attempt_at: now,
        created_at: now,
        updated_at: now,
    };
}

async function expectDatabaseError(
    operation: PromiseLike<unknown>,
    expectedText: string
): Promise<void> {
    let failure: unknown;
    try {
        await operation;
    } catch (error) {
        failure = error;
    }
    expect(failure).to.be.instanceOf(Error);
    expect(errorText(failure)).to.include(expectedText);
}

async function explainText(database: Knex, statement: string): Promise<string> {
    const result = await database.raw(`explain ${statement}`);
    return result.rows
        .map((row: Record<string, string>) => row["QUERY PLAN"])
        .join("\n");
}

function errorText(value: unknown, seen = new Set<object>()): string {
    if (value === null || value === undefined) return "";
    if (typeof value !== "object") return String(value);
    if (seen.has(value)) return "";
    seen.add(value);

    const parts: string[] = [];
    if (value instanceof Error) {
        parts.push(value.name, value.message, value.stack ?? "");
    }
    for (const key of Object.getOwnPropertyNames(value)) {
        if (["name", "message", "stack"].includes(key)) continue;
        try {
            parts.push(
                errorText((value as Record<string, unknown>)[key], seen)
            );
        } catch {
            // Ignore getters that throw while inspecting a failure object.
        }
    }
    return parts.join("\n");
}

function testS3Config() {
    return {
        bucket: "postgres-failure-test",
        endpoint: "http://127.0.0.1:1",
        accessKeyId: "unused-access-key",
        secretAccessKey: "unused-secret-key",
    };
}
