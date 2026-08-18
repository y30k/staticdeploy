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
            expect(first[1]).to.deep.equal(["00.js", "01.js", "02.js"]);
            expect(await applicationTables(database)).to.deep.equal([
                "apps",
                "bundles",
                "entrypoints",
                "groups",
                "operationLogs",
                "users",
                "users_groups",
            ]);
            expect(await migrationNames(database)).to.deep.equal([
                "00.js",
                "01.js",
                "02.js",
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
            ]);

            const second = await database.migrate.latest(
                productionMigrationConfig
            );
            expect(second[1]).to.deep.equal([]);
            expect(await migrationNames(database)).to.deep.equal([
                "00.js",
                "01.js",
                "02.js",
            ]);
        });
    });

    it("SCH-02 accepts a captured post-02 schema without changing data, FKs, or history", async () => {
        await withDisposableDatabase(admin, async (database) => {
            await installLegacyFixture(database, "post02");
            const before = await legacySnapshot(database);

            const result = await database.migrate.latest(
                productionMigrationConfig
            );

            expect(result[1]).to.deep.equal([]);
            expect(await migrationNames(database)).to.deep.equal([
                "00.js",
                "01.js",
                "02.js",
            ]);
            expect(await legacySnapshot(database)).to.deep.equal(before);
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
            expect(first[1]).to.deep.equal(["02.js"]);
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
            ]);
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
        for (const name of ["00", "01", "02"]) {
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
