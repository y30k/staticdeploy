import { Knex, knex } from "knex";

export interface IPostgresClientOptions {
    poolMin: number;
    poolMax: number;
    poolIdleTimeoutMillis: number;
    acquireConnectionTimeoutMillis: number;
    connectionTimeoutMillis: number;
}

export const defaultPostgresClientOptions: Readonly<IPostgresClientOptions> = {
    poolMin: 0,
    poolMax: 10,
    poolIdleTimeoutMillis: 30_000,
    acquireConnectionTimeoutMillis: 10_000,
    connectionTimeoutMillis: 5_000,
};

/**
 * Construct the shared PostgreSQL client with explicit, bounded connection
 * behavior. Options are injectable for focused pool/failure tests, but the
 * service intentionally exposes no additional environment configuration.
 */
export function createPostgresKnex(
    postgresUrl: string,
    options: IPostgresClientOptions = defaultPostgresClientOptions
): Knex {
    const config: Knex.Config = {
        client: "pg",
        connection: {
            connectionString: postgresUrl,
            connectionTimeoutMillis: options.connectionTimeoutMillis,
        },
        pool: {
            min: options.poolMin,
            max: options.poolMax,
            idleTimeoutMillis: options.poolIdleTimeoutMillis,
            acquireTimeoutMillis: options.acquireConnectionTimeoutMillis,
        },
        acquireConnectionTimeout: options.acquireConnectionTimeoutMillis,
    };

    return knex(config);
}
